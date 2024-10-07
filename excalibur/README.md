A simple circuit visualizer for Placeholder proof system.

# Building and running
1. Do a `nix develop .#excalibur` in the directory above this one
2. Run `eval $configurePhase`
3. `ninja excalibur`
4. If you encounter an error while trying to open a file, you need to compile the GTK schema used in the dialog, and link the environment variable. In order to do that, find you gtk installation in `/nix/store/`.

The best way of doing this is via `nix-locate org.gtk.gtk4.Settings.FileChooser.gschema.xml` if you have [nix-index](https://github.com/nix-community/nix-index) installed.

Alternatively, run `schema-locator.sh`. If you have multiple versions of gtk4 in the store, use the latest one.

After finding the file, run `glib-compile-schemas --targetdir=. /path/to/schema/directory`.
Note that you need to pass *directory*, and not the file path.
This should create `gschemas.compiled` file in current (build) directory.

Export the `gschemas.compiled` directory via `export GSETTINGS_SCHEMA_DIR=/path/to/compiled/schema/dir`.

Run `./src/excalibur --vesta` (or `--pallas`, or one of the other supporting curves).

# FAQ
I get the following error while running the tool:
```
(excalibur:24987): GLib-GIO-ERROR **: 18:39:52.016: Settings schema 'org.gtk.gtk4.Settings.FileChooser' is not installed
Trace/breakpoint trap
```
Check that you've done step 4 above. Export has to be redone each shell session, unless you modify `.bashrc` or do something similar.

How do I export my circuit/assignment table?

Use `export_table` (defined in `include/nil/blueprint/blueprint/plonk/assignment.hpp`) for exporting the assignment table, and `export_circuit` (defined in in `include/nil/blueprint/blueprint/plonk/circuit.hpp`) for circuit export.
A good place to call the export functions might be `test_plonk_component.hpp`.

There currently is no compiler integration.

Lookup constraints support is not implemented yet.
