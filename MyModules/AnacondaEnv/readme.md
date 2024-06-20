### Anaconda `activate.bat` Clone for Powershell

Created in reponse to this issue: https://github.com/ContinuumIO/anaconda-issues/issues/311

This module will mimic Anaconda's `activate` function almost completely, allowing users to mimic the Anaconda Prompt in Powershell.

### How To Use

Example usage: https://gist.github.com/pldmgg/c84e802bcecd6e4c962f65be5b5d316d

### Functionality

+ Sets the `python` path to the appropriate Anaconda environment.

+ Sets `conda` to the Anaconda base `conda.exe`

+ Sets up propert encoding and overhead for running Anaconda Python in the PS terminal.

+ Does not map `pip`, `easy_install`, `conda install`, or similar package managers to the appropriate virtual environment. Always maps them to the base environment. Run `pip --version`, `Get-Command conda`, or similar, to verify this.

### TODO

+ Fix issues regarding mapping `pip`, `easy_install`, and `conda install` to the appropriate virtual environment.


