# Sample for the Eclypses MTE / SDR 2.0
## Introduction
The *Eclypses MTE* library is a patented system that protects any kind of data in a way that is impossible to decipher.
The internal workings of this library have been *FIPS 140-3* validated by an independent lab.  
When information must be protected and then later consumed by a disconnected subscriber, it must be created in a way
that makes the producer and consumer independent.  To accomplish this, Eclypses has developed the *SDR (Secure Data Replacement)*
add-on.  This solution demonstrates that add-on which is ideal for *"Load and Go"* use cases as well as loosely coupled
solutions that utilize a *pub/sub* architecture or a queuing service such as *Kafka* or *RabbitMQ*.
## Project Structure
This demonstration application is divided into two distinct modules.
### Eclypses.SDR.Sample.Producer
This is a C++ project that takes any file and protects it in a way that cannot be reverse-engineered. It consists of the
following modules:
- *Eclypses.SDR.Sample.Producer.cpp* -- This is the main executable that merely reads a file and then  protects it.  
- *MteSdr* -- This is the *c++* language wrapper that exposes the methods in the *mte.dll* library.
- *MteSdrDisconnected.cpp* -- This is a derivation of *MteSdr.cpp* that exposes the following methods:
	- sdrInit -- This initializes the environment.
	- Conceal -- This takes a pointer to a byte array and protects it.
	- Reveal -- This takes a pointer to a protected byte array and re-constitutes it.

### Eclypses.SDR.Sample.Consumer
This is a C++ project that takes a protected file and reconstitutes it into its original form.
It consists of the following modules:
- *Eclypses.SDR.Sample.Consumer.cpp* -- This is the main executable that merely reads a protected file and then reconstitutes it.
- *MteSdr* -- This is the *c++* language wrapper that exposes the methods in the *mte.dll* library.
- *MteSdrDisconnected.cpp* -- This is a derivation of *MteSdr.cpp* that exposes the following methods:
	- sdrInit -- This initializes the environment.
	- Conceal -- This takes a pointer to a byte array and protects it.
	- Reveal -- This takes a pointer to a protected byte array and re-constitutes it.

## Usage
To try this out, after building the solution a folder named *./x64/Debug* which contains
executable versions of the two modules detailed above will be found in the main solution folder. Follow these steps:  
- Obtain your *Eclypses MTE Library* (*mte.dll*), your licensed company name, and your license key
from the Eclypses Dev Portal at *https://developers.eclypses.com*.
- Create a *settings.txt* file and ensure that your licensed company and license key are correct (this file is the same for the *Producer* and *Consumer*). An example follows:
```
# This file contains the license info
# It is CaseSensitive and looks for
# the value AFTER the "=" sign, so
# do not include any spaces!
LicensedCompany=mylicensedcompanyname
LicenseKey=mylicensekey
```  
- Run the *Producer*, you will be prompted for a file name to protect. 
- Once you enter a file name and press *enter*, a file will be produced in this directory with
the original file name and *.sdr* appended to it.
- You may then run the *Consumer* and when prompted, enter the *sdr* file that was
just produced.  
- This will result in a file named *"original".sdr.clear*.  This file is identical
to your original file that you protected.  
- You can run this multiple times and examine the *sdr* files to see that even though
the original file is the same, the *sdr* file is quite different.  
 
However, any *sdr* file can be re-constituted as long as the **same** *mte.dll* is used
for both the *Producer* and the *Consumer* and the
**same** security string is used.

### To Build this
If you wish to build this, you will need to copy the files
from the *lib* folder in your downloaded SDK into the *lib*
folder of your solution.  These files are your licensed
Eclypses MTE.

## Source Code
This is a *Windows c++* project created in Visual Studio 2022.  You are free to examine the source which
is commented quite heavily. If you are testing this in Visual Studio, make sure that your *settings.txt* file and the *mte.dll* are in the same project since they are required to test. Since this is intended to be a quick demonstration,
there is not a lot of error checking. It should ***NOT*** be used in a production environment.  
With the ***MteSdrDisconnected*** class and the ***mte.dll*** it is quite
straight-forward to implement in your own applications.
 
 ## Further Information
 To obtain further information about *Eclypses* and its offerings, visit *https://eclypses.com/*. You may obtain technical documentation at *https://public-docs.eclypses.com/*.