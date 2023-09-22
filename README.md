# Terraform Provider for (Operating) System

## NOTICE: EXPERIMENTAL

This is a fork of https://github.com/neuspaces/terraform-provider-system

It is highly experimental, and may not be working. Use at your own risk.

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/robbert229/terraform-provider-system)](https://github.com/robbert229/terraform-provider-system/releases)
[![main](https://github.com/robbert229/terraform-provider-system/actions/workflows/main.yml/badge.svg)](https://github.com/robbert229/terraform-provider-system/actions/workflows/main.yml)
[![GitHub Discussions](https://img.shields.io/github/discussions/robbert229/terraform-provider-system)](https://github.com/robbert229/terraform-provider-system/discussions)
[![GitHub License](https://img.shields.io/github/license/robbert229/terraform-provider-system)](https://github.com/robbert229/terraform-provider-system/blob/main/LICENSE)
[![Terraform Registry](https://img.shields.io/badge/terraform-registry-5c4ee5.svg)](https://registry.terraform.io/providers/robbert229/system/latest)

Releases: [registry.terraform.io](https://registry.terraform.io/providers/robbert229/system/latest)

Documentation: [registry.terraform.io](https://registry.terraform.io/providers/robbert229/system/latest/docs)

Discuss: [github.com/discussions](https://github.com/robbert229/terraform-provider-system/discussions)

The Terraform Provider for (Linux Operating) System allows managing files, directories, users, groups, packages, and services on remote servers on operating system level agent-less via SSH.

> Even in a cloud-native heaven ☁️, there will still be use cases for pets 🐈

## Highlights

* Manage files, directories, users, groups, packages, and services on remote servers
* Connect to and authenticate with remote servers via SSH
* No agent on remote server required
* Seamless integration with Terraform providers of [all major IaaS cloud providers](examples)
* Support for Debian, Alpine, and Fedora Linux confirmed via acceptance test suite

## Quick Starts

- [Using the provider](https://registry.terraform.io/providers/robbert229/system/latest/docs)
- [Examples](examples)

## Use Cases

The provider aims to allow configuring individual remote servers according to *mutable infrastructure* approach. You might find your use case in the following non-exhaustive list:

* Individual servers or virtual machines which are not recreated when configuration changes
* Share or distribute server or virtual machine configuration as using Terraform modules

The provider is not suitable for *immutable infrastructure* approaches such as fleets of homogeneous virtual machines. In this case, you may consider a more suitable configuration mechanism.

## User documentation

Refer to the comprehensive [user documentation of the provider in the Terraform Registry](https://registry.terraform.io/providers/robbert229/system/latest/docs).

## Frequently Asked Questions

Responses to the most frequently asked questions can be found in the [FAQ](https://registry.terraform.io/providers/robbert229/system/latest/docs/guides/faq).

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) 0.12+
