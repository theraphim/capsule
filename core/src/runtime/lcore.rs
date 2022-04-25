/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use crate::ffi::dpdk::{self, DpdkLcoreError, LcoreId, LcoreState, MempoolPtr};
use crate::info;
use crate::runtime::MEMPOOL;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::ops::DerefMut;
use thiserror::Error;
use triggered::{trigger, Listener, Trigger};

/// An abstraction on top of a DPDK logical core.
pub struct Lcore {
    id: LcoreId,
    shutdown: (Trigger, Listener),
}

/// Lcore error.
#[derive(Debug, Error)]
pub enum LcoreError {
    #[error("dpdk lcore error")]
    DpdkLcoreError(#[from] DpdkLcoreError),
    #[error("lcore {0} not found")]
    NotFound(usize),
    #[error("lcore {0:?} not ready")]
    NotReady(LcoreId),
}

impl Lcore {
    /// Creates a new LCore instance to manage tasks on this lcore
    ///
    /// # Errors
    ///
    /// Returns `Error` if the given lcore is not in the WAIT state
    fn new(id: LcoreId) -> Result<Self, LcoreError> {
        match dpdk::eal_get_lcore_state(id) {
            Ok(LcoreState::WAIT) => Ok(Lcore {
                id,
                shutdown: trigger(),
            }),
            Err(e) => Err(e.into()),
            _ => Err(LcoreError::NotReady(id)),
        }
    }

    /// Checks if the LCore is ready to have tasks executed on it
    pub fn is_ready(&self) -> Result<bool, LcoreError> {
        Ok(matches!(
            dpdk::eal_get_lcore_state(self.id())?,
            LcoreState::WAIT
        ))
    }

    /// Checks if the LCore is currently running
    pub fn is_running(&self) -> Result<bool, LcoreError> {
        Ok(!self.shutdown.1.is_triggered()
            && matches!(dpdk::eal_get_lcore_state(self.id())?, LcoreState::RUNNING))
    }

    /// Sets the thread local mempool for this lcore
    pub(crate) fn add_mempool(&self, mut mempool: MempoolPtr) -> Result<(), LcoreError> {
        if !self.is_ready()? {
            return Err(LcoreError::NotReady(self.id));
        }
        dpdk::eal_remote_launch(self.id(), move || -> Result<Option<i32>, Infallible> {
            MEMPOOL.with(|tls| tls.set(mempool.deref_mut()));
            Ok(None)
        })?;
        dpdk::eal_wait_lcore(self.id())?;
        Ok(())
    }

    /// Returns the lcore id.
    pub(crate) fn id(&self) -> LcoreId {
        self.id
    }

    /// Spawns a function to be looped on this lcore
    ///
    /// # Errors
    ///
    /// Returns `Error` if the lcore is not in the WAIT state
    pub fn run_loop<RunFn>(&self, looped_fn: RunFn) -> Result<(), LcoreError>
    where
        RunFn: Fn() -> () + Send + 'static,
    {
        if !self.is_ready()? {
            return Err(LcoreError::NotReady(self.id));
        }
        let listener = self.shutdown.1.clone();
        let id = self.id().clone();
        dpdk::eal_remote_launch(self.id(), move || -> Result<Option<i32>, Infallible> {
            info!(?id, "lcore function started.");
            while !listener.is_triggered() {
                looped_fn();
            }
            info!(?id, "lcore function stopped.");
            Ok(None)
        })?;
        Ok(())
    }

    /// Spawns a function to be run once on this lcore
    ///
    /// # Errors
    ///
    /// Returns `Error` if the lcore is not in the WAIT state
    pub fn run_single<RunFn, RunFnError>(&self, run_fn: RunFn) -> Result<(), LcoreError>
    where
        RunFnError: Error,
        RunFn: FnOnce(Listener) -> Result<Option<i32>, RunFnError> + Send + 'static,
    {
        if !self.is_ready()? {
            return Err(LcoreError::NotReady(self.id));
        }
        let id = self.id().clone();
        let listener = self.shutdown.1.clone();
        dpdk::eal_remote_launch(self.id(), move || -> Result<Option<i32>, RunFnError> {
            info!(?id, "lcore function started.");
            let result = run_fn(listener);
            info!(?id, "lcore function stopped.");
            result
        })?;
        Ok(())
    }

    /// Shuts down the current task and returns the result
    pub fn join(&mut self) -> Result<Option<i32>, LcoreError> {
        self.shutdown.0.trigger();
        Ok(dpdk::eal_wait_lcore(self.id())?)
    }
}

impl fmt::Debug for Lcore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lcore").field("id", &self.id()).finish()
    }
}

impl Drop for Lcore {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

/// Map to lookup the lcore by the assigned id.
#[derive(Debug)]
pub struct LcoreMap(HashMap<usize, Lcore>);

impl LcoreMap {
    /// Returns the lcore with the assigned id.
    pub fn get(&self, id: usize) -> Result<&Lcore, LcoreError> {
        self.0.get(&id).ok_or_else(|| LcoreError::NotFound(id))
    }

    /// Returns a lcore iterator.
    pub fn iter(&self) -> impl Iterator<Item = &Lcore> {
        self.0.values()
    }
}

impl From<Vec<Lcore>> for LcoreMap {
    fn from(lcores: Vec<Lcore>) -> Self {
        let map = lcores
            .into_iter()
            .map(|lcore| (lcore.id.raw(), lcore))
            .collect::<HashMap<_, _>>();
        LcoreMap(map)
    }
}

/// Returns the enabled worker lcores.
pub(crate) fn lcore_pool() -> LcoreMap {
    let mut lcores = Vec::new();
    let mut current = None;

    while let Some(id) = dpdk::get_next_lcore(current, true, false) {
        lcores.push(Lcore::new(id).unwrap());
        current = Some(id);
    }

    lcores.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use std::thread;

    #[capsule::test]
    fn get_current_lcore_id_from_eal() {
        let next_id = dpdk::get_next_lcore(None, true, false).expect("panic!");
        let mut lcore = Lcore::new(next_id).expect("panic!");
        lcore
            .run_single(|_| {
                let id: u32 = LcoreId::current().into();
                Ok(Some(id.try_into()?))
            })
            .unwrap();
        let id: u32 = lcore
            .join()
            .unwrap()
            .ok_or(anyhow!("No result"))
            .unwrap()
            .try_into()
            .unwrap();
        let lcore_id: LcoreId = id.into();
        assert_eq!(next_id, lcore_id);
    }

    #[capsule::test]
    fn get_current_lcore_id_from_non_eal() {
        let lcore_id = thread::spawn(LcoreId::current).join().expect("panic!");

        assert_eq!(LcoreId::ANY, lcore_id);
    }
}
