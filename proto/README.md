
Protobuf Definitions & Generated Code
=======

The `proto/` directory quite mimics the contents of its parent, and for each type directory
in the repository root, there is an equivalent directory where Protobuf definitions are.
As well, all files for managing the code generation and customization are listed below.

#### Management
- `buf.yaml`        - Manage Protobuf code dependencies and global linting.
- `buf.work.yaml`   - Declare directories of interest for Protobuf compilation
- `buf.gen.yaml`    - Manage the various plugins for code generation and customization.
- `buf.lock`        - Lockfile for Protobuf dependencies.

### Generated Code
- `proto/gen/`      - All generated code, for a directory per language (eg. `gen/go`)
