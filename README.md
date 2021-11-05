
Attacked Infrastructure Modular Specification (AIMS)
======

## Overview

This repository aims to gather various declarations/specification of elements faced or needed
in offensive security tasks, to be used and consumed by securiy tools. This might be somewhat compared
to MISP and STIX specifications, except that we are here considering objects of interest for attackers.
There is no functional logic code in the project: just types and their own facilities.

Many tools and frameworks are bound to their own object types (often because either language-agnostic 
specifications are not possible, or they didn't write them), and therefore passing their outputs as 
inputs to other tools might be sometimes complicated. Various data formats have helped along the way, 
but interoperability still lacks in some places.

Also, because storing these objects in traditonal SQL-like Databases is somewhat contradictory and
because directly declaring SQL-compliant objects can be a pain, most of the types found out there
are hard to move from one DB system to another.

Summarizing, this repository aims to give access to objects & types encountered in security tasks,
in a way that makes them easy to be moved around, registered and stored in SQL-like databases, and
which optionally support helpers code to be declared along, for instance to implement some interfaces.

Protobuf definitions being prevalent today and having good builtin/plugin support for many languages,
the base declarations of objects will be found in `.proto` files. Besides, because the tooling for Go
is quite advanced and the language has a nice support for builtin data format marshalling, the first
phase of the project's code is generated in Go. Please see below for other reasons.


## Aims 

The repository wish to provide several primary "guarantees" about/along with the objects 
it provides. Some of these guarantees are related to the Go-generated code for these objects:
- Using all objects as Go native types.
- The user-facing types are Protobuf-compliant Go types (generated code)
- These types can be easily stored, updated, deleted in a SQL-database (GORM is our driver here) .
- The Go types are tagged so as to support various tools' data formats (eg. nmap' XML) out of the box.
- All objects have an exhaustive list of attributes, so that users may wish to populate those they need.
- Most types have sane DB-behavior defaults, such as deleting on cascade, etc.

Along with these, the repo has another set of secondary (sometimes more tool-specific) aims:
- The ability for most objects to express themselves as valid Maltego Entities.
- A few default Database profiles, to be consumed by users storing their objects and needing to customize behavior.


## Tools & Technologies

The following technologies, libraries and tools are core pillars of the project:
- Protocol Buffers
- GORM (Go Relational Models)
- Go plugins for struct tagging
- Go Maltego library
- Buf Build for managing code generation/customization


## User & Developer Documentation

The repository contains a Wiki documentation where are explained:
- How to make use of existing types in your own projects, in various contexts.
- How to add fields to existing types and generate the new updated code. 
- How to use and customize the overall DB behaviors, should you want to store your objects.
- How to use tags and various Protobuf options to make your types/field available in other ways.
- Some examples and use cases with more complete workflows.


<!-- ## Typical Object Specification & Development Workflow -->


## Code Structure

The code structure for the project is the following, with some brief descriptions for each part.
Most of the subdirectories will often include their own README, especially when they have some
context that is peculiar to them.

#### Core 
- `credential/`     - Access and secret management related objects, including all cryptographic ones.
- `host/`           - Types related to a physical/virtual host, considering the latter non-networked.
- `network/`        - Types associated to computer networks, like IP addresses, services, routes, etc.
- `scan/`           - Types related to various forms of scanning, sometimes in their own tool directory (eg. nmap)

#### Management
- `buf.yaml`        - Manage Protobuf code dependencies and global linting.
- `buf.work.yaml`   - Declare directories of interest for Protobuf compilation
- `buf.gen.yaml`    - Manage the various plugins for code generation and customization.
- `buf.lock`        - Lockfile for Protobuf dependencies.

### Go
- `go.mod`/`go.sum` - The repository module management.
- `vendor/`         - All vendored Go dependencies.


## Individual Package/Directory 

This sections describes the code structure for a single subdirectory. The reason for this is primarily
that Go code is packaged per-directory, and forbids any form of circular imports (just as Protobuf does).

The structure tries to provide the following advantages:
- Most of the DB helper code generated by GORM is hidden from the user API.
- Declutters the directory contents by moving Protobuf definitions and generated code out of the package you use.
- Gives place in the user-facing package for user-facing helper code, such as Maltego Entity interface implementations.

The following structure is applied:
- `proto/`      - All Protobuf definitions for a package.
- `gen/`        - All generated code, per language (eg. `gen/go`, `gen/java`, etc)
- `object.go`   - A reexport of an `Object` type somewhere in `gen/`, including all its user-facing helpers.
