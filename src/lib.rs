//! Argos Panoptes - Web Security Scanner for Healthcare Environments
//!
//! A modular web security scanner that analyzes websites for vulnerabilities,
//! misconfigurations, and security issues. Generates professional HTML reports
//! with findings categorized by severity.

pub mod config;
pub mod crawler;
pub mod error;
pub mod http;
pub mod models;
pub mod oob;
pub mod proxy;
pub mod report;
pub mod scanner;
