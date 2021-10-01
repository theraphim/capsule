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

use crate::ffi::dpdk::{self, LcoreId, LcoreState, MempoolPtr};
use crate::{info};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use triggered::{Listener, Trigger, trigger};
use crate::runtime::MEMPOOL;
use std::ops::DerefMut;

/// An abstraction on top of a DPDK logical core.
pub struct Lcore {
    id: LcoreId,
    shutdown: (Trigger, Listener)
}

impl Lcore {
    /// Creates a new LCore instance to manage tasks on this lcore
    ///
    /// # Errors
    ///
    /// Returns `Error` if the given lcore is not in the WAIT state
    fn new(id: LcoreId) -> Result<Self> {
        match dpdk::eal_get_lcore_state(id) {
            Ok(LcoreState::WAIT) =>
                Ok(Lcore {
                    id,
                    shutdown: trigger()
                }),
            Err(e) => Err(e),
            _ => {
                Err(anyhow!("LCore not ready"))
            }
        }
    }

    /// Checks if the LCore is ready to have tasks executed on it
    pub fn is_ready(&self) -> Result<bool> {
        Ok(
            match dpdk::eal_get_lcore_state(self.id())? {
                LcoreState::WAIT => true,
                _ => false,
            }
        )
    }

    /// Checks if the LCore is currently running
    pub fn is_running(&self) -> Result<bool> {
        Ok(
            !self.shutdown.1.is_triggered() &&
            match dpdk::eal_get_lcore_state(self.id())? {
                LcoreState::RUNNING => true,
                _ => false,
            }
        )
    }

    /// Sets the thread local mempool for this lcore
    pub(crate) fn add_mempool(&self, mut mempool: MempoolPtr) -> Result<()> {
        if !self.is_ready()? {
            return Err(anyhow!("Lcore not ready"));
        }
        dpdk::eal_remote_launch(self.id(),
                                move || {
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
    pub fn run_loop<F>(&self, looped_fn: F) -> Result<()> where F: Fn() -> () + Send + 'static {
        if !self.is_ready()? {
            return Err(anyhow!("Lcore not ready. Perhaps you forgot to `join` the last execution?"));
        }
        let listener = self.shutdown.1.clone();
        let id = self.id().clone();
        dpdk::eal_remote_launch(self.id(), move || {
            info!(?id, "lcore function started.");
            while !listener.is_triggered() {
                looped_fn();
            }
            info!(?id, "lcore function stopped.");
            Ok(None)
        })
    }

    /// Spawns a function to be run once on this lcore
    ///
    /// # Errors
    ///
    /// Returns `Error` if the lcore is not in the WAIT state
    pub fn run_single<F>(&self, run_fn: F) -> Result<()> where F: FnOnce(Listener) -> Result<Option<i32>> + Send + 'static {
        if !self.is_ready()? {
            return Err(anyhow!("Lcore not ready"));
        }
        let id = self.id().clone();
        let listener = self.shutdown.1.clone();
        dpdk::eal_remote_launch(self.id(), move || {
            info!(?id, "lcore function started.");
            let result = run_fn(listener);
            info!(?id, "lcore function stopped.");
            result
        })
    }

    /// Shuts down the current task and returns the result
    pub fn join(&mut self) -> Result<Option<i32>> {
        self.shutdown.0.trigger();
        dpdk::eal_wait_lcore(self.id())
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

/// Lcore not found error.
#[derive(Debug, Error)]
#[error("lcore not found.")]
pub struct LcoreNotFound;

/// Map to lookup the lcore by the assigned id.
#[derive(Debug)]
pub struct LcoreMap(HashMap<usize, Lcore>);

impl LcoreMap {
    /// Returns the lcore with the assigned id.
    pub fn get(&self, id: usize) -> Result<&Lcore> {
        self.0.get(&id).ok_or_else(|| LcoreNotFound.into())
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
    use std::thread;
    use std::convert::TryInto;

    #[capsule::test]
    fn get_current_lcore_id_from_eal() {
        let next_id = dpdk::get_next_lcore(None, true, false).expect("panic!");
        let mut lcore = Lcore::new(next_id).expect("panic!");
        lcore.run_single(|_| {
            let id: u32 = LcoreId::current().into();
            Ok(Some(id.try_into()?))
        }).unwrap();
        let id: u32 = lcore.join().unwrap().ok_or(anyhow!("No result")).unwrap().try_into().unwrap();
        let lcore_id: LcoreId = id.into();
        assert_eq!(next_id, lcore_id);
    }

    #[capsule::test]
    fn get_current_lcore_id_from_non_eal() {
        let lcore_id = thread::spawn(LcoreId::current).join().expect("panic!");

        assert_eq!(LcoreId::ANY, lcore_id);
    }
}
