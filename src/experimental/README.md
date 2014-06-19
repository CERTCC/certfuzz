# About the experimental directory #

These are things that were spinoffs from the main BFF and FOE development effort. They worked at a point in time, but aren't actively supported and we have no plans to develop them further at this time. Although they're not in a fully releasable form, we figured somebody might find some of it useful if they're willing to dig a bit.

## android ##

In 2013 we put some effort into porting BFF to work on Android. The idea was that you'd start with the BFF linux VM and install the Android SDK. The basic program flow is as follows: BFF for Android runs in the linux machine. It clones AVDs, fuzzes seed files, copies fuzzed files into the AVD's SD card, injects an explicit intent to tell an app to open the fuzzed file, and checks to see if the app crashed by looking for a tombstone. If it finds one, it collects data about the crash and dumps it into a couchdb instance. We got approximately that far, but the project ended and we haven't revisited it since. See also the code in `certfuzz\android` for implementation details. However, our subsequent experience is that file parsing vulnerabilities are pretty far down the list of ways you can attack Android apps -- there are any number of lower hanging fruit. 

## aws ##

This was a student project by Shaun Blackburn. We gave him a copy of BFF 2.6 and asked him to make it work in AWS, which he did. The resulting cloudinit script is here, along with some slides and a readme for background. It worked in the spring of 2013, but we are not actively maintaining it. 
