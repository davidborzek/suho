// SPDX-License-Identifier: GPL-3.0-or-later
//! Versioned policy API.
//!
//! Each API version lives in its own module, Kubernetes-style
//! (`v1alpha1` → `v1beta1` → `v1`): the label/file schema a given version
//! accepts is defined by that module's types. Only [`v1alpha1`] exists today;
//! new versions are added alongside it so old inputs keep parsing.

pub mod v1alpha1;
