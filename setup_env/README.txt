This directory is an experiment in progress.

Based on the responses to 
http://stackoverflow.com/questions/6590688/is-it-bad-to-have-my-virtualenv-directory-inside-my-git-repository

I (adh) wanted to try automating the creation and initialization of a virtualenv for BFF.

What's in here:
* deploy_virtualenv.sh - Creates a virtualenv named bff.env, activates it, and attempts to pip install the 
requirements listed in requirements.txt.
* pip_freeze.sh - Dumps currently installed pip packages into a list found in requirements.txt. Note that the
raw dump may include packages not relevant to BFF, so it will likely require editing prior to use. (or any commits)
* README.txt - this file
* requirements.txt - The list of pip packages that will be installed by deploy_virtualenv.sh
