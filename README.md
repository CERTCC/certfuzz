This project contains the source code for the CERT Basic Fuzzing Framework (BFF)

BFF for Windows was formerly known as the CERT Failure Observation Engine (FOE).

## If you are looking for runnable code, you should download the latest releases at: 

[BFF](https://resources.sei.cmu.edu/forms/bff-download.cfm)

## Using this code 

Depending on your preferred level of difficulty and experience points, choose from the options below.

### Easy

Most of the BFF code can be found in the certfuzz package `src/certfuzz`. To try out the certfuzz code in an existing installation of BFF, replace the `certfuzz` directory in your installation with the `certfuzz` directory found in this repository.

### Moderate

Some platform-specific stuff is in `src/windows` and `src/linux`. BFF for OSX uses `src/linux` too. See `src/linux/README` and `src/windows/README.txt` for platform-specific readmes, and `src/linux/INSTALL` if you are feeling extra adventurous.

### Hard

We actually use a continuous integration system with some platform-specific tools in conjunction with the code in the `build/` directory to build the releases found at the links above. However, at this time the build code is not expected to work anywhere other than that environment. In fact, the code in the master branch is svn-centric so it didn't even work when we switched to git. We've fixed that in our internal development system, but have not yet merged that in with the code posted here.

Furthermore, the build scripts modify some files and move things around to put together the release packages and build installers. The filenames (but not necessarily the locations) in the `src/` directories usually stay intact though so you should be able to figure out where things go if you are looking outside the `src/certfuzz` directory. (As mentioned in the *Easy* section above, `src/certfuzz` should just be a drop-in replacement.)

If all that seems more like a challenge than a warning, go for it.

### Experimental 

See `src/experimental/README.md` for some dead ends that might be marginally useful.

## About BFF 

The CERT Basic Fuzzing Framework (BFF) is a software testing tool that finds defects in applications that run on Linux, Mac OS X and Windows.

BFF performs mutational fuzzing on software that consumes file input.  They automatically collect test cases that cause software to crash in unique ways, as well as debugging information associated with the crashes. The goal of BFF is to minimize the effort required for software vendors and security researchers to efficiently discover and analyze security vulnerabilities found via fuzzing.

Mutational fuzzing is the act of taking well-formed input data and corrupting it in various ways, looking for cases that cause crashes. BFF automatically collects test cases that cause software to crash in unique ways, as well as debugging information associated with the crashes. The goal of BFF is to minimize the effort required for software vendors and security researchers to efficiently discover and analyze security vulnerabilities found via fuzzing.

Traditionally, fuzzing has been very effective at finding security vulnerabilities, but because of its inherently stochastic nature, results can be highly dependent on the initial configuration of the fuzzing system. BFF applies machine learning and evolutionary computing techniques to minimize the amount of manual configuration required to initiate and complete an effective fuzzing campaign. BFF adjusts its configuration parameters based on what it finds (or does not find) over the course of a fuzzing campaign. By doing so it can dramatically increase both the efficacy and efficiency of the campaign. As a result, expert knowledge is not required to configure an effective fuzz campaign, and novices and experts alike can start finding and analyzing vulnerabilities very quickly.

The following are some of the specific features that are available in BFF:

- Minimal initial configuration is required to start a fuzzing campaign.
- Minimal supervision of the fuzzing campaign is required, as BFF can automatically recover from many common problems that can interrupt fuzzing campaigns.
- Uniqueness determination is handled through intelligent backtrace analysis.
- Automated test-case minimization reduces the effort required to analyze results. This is achieved by distilling the test case to the minimal changes to the input data required to induce a specific crash.
- Online machine learning is applied to fuzzing parameter and input file selection to improve the efficacy of the campaign.
- Crash severity/exploitability triage is provided.

At the CERT/CC, we have used the BFF infrastructure to find a number of critical vulnerabilities in products such as Adobe Reader and Flash Player; Foxit Reader; Apple QuickTime, Preview, and Mac OS X; Xpdf; Poppler; FFmpeg; JasPer; Wireshark; VMware VMnc video codec; the Indeo video codec; and many others. See [Public Vulnerabilities Discovered Using BFF](https://github.com/CERTCC/certfuzz/wiki/Public-Vulnerabilities-Discovered-Using-BFF).

### A brief history of BFF and FOE ##

BFF and FOE started out as two separate but related projects within the CERT/CC
Vulnerability Analysis team. Over time, they converged in their architecture to the point where BFF 2.7 and FOE 2.1 shared much of their code. As of BFF 2.8, this integration is complete and we have retired the name FOE in favor of BFF.


## For more information

Blog posts about BFF and FOE can be found in the [CERT/CC Vulnerabilities](https://insights.sei.cmu.edu/blog/topics/certcc/) category on the [SEI Blog](https://insights.sei.cmu.edu/blog/)
