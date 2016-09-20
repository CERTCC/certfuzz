# About the experimental directory #

These are things that were spinoffs from the main BFF and FOE development effort. They worked at a point in time, but aren't actively supported and we have no plans to develop them further at this time. Although they're not in a fully releasable form, we figured somebody might find some of it useful if they're willing to dig a bit.

## aws ##

This was a student project by Shaun Blackburn. We gave him a copy of BFF 2.6 and asked him to make it work in AWS, which he did. The resulting cloudinit script is here, along with some slides and a readme for background. It worked in the spring of 2013, but we are not actively maintaining it. 

## setup_env ##

We started to look at being able to use BFF in a virtualenv, but since we usually recommend dedicated VMs for fuzzing this turned out to be less useful than we originally thought, so we didn't proceed any further. We might come back to this in the future though.

## setup.py ##

Pretty much the same argument as setup_env above. We might revisit it later but it wasn't necessary for now.

## stats_and_other_tools ##

The new architecture we implemented in BFF 2.8 broke some older tools that were originally useful as we developed minimizer but weren't all that useful for people fuzzing with our tools. Just moving the entry point script out of the way here.

