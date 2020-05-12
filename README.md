# ams_fatal_inspector
An IDA plugin for navigating a Nintendo Switch binary based on an Atmosphère fatal error report.

## Installation
Copy `ams_fatal_inspector.py` to your IDA `plugins` directory.

## Usage
The plugin can be started from `Edit->Plugins->Atmosphère fatal report inspector` or using the hotkey combination `Ctrl + Alt + A`.

Use the file browser to open an Atmosphère fatal error report log. This will parse the stack trace return addresses and display the traceback as a table of addresses and containing function names. Double clicking a row in the table will jump to that address.
