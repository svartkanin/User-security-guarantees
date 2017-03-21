# Providing User Security Guarantees in Lightweight Virtualization Infrastructure

## What's this

This system was developed during a research project conducted with RISE SICS (https://www.sics.se/projects/5g-ensure). It is a protype of its kind and for sure can be extended in many ways. The purpose of such system is to provide a user, in charge of an SDN controller, with certain security guarantees towards the application layer, so that the applications accessing the controller can be considered trustworthy. 
The applications are being considered to run inside a Docker container on a remote host. To be able to guarantee the integrity of the remote host, Linux IMA is used to check the integrity of the remote system. The measurement results of IMA are sent to the controller, where they are validated. In addition to IMA, Intel's SGX (Software Guard Extension) is used to encrypt and store sensitive data. After the IMA meassurement list has been validated successfully, the application running inside a container will be validated as well. If this validation has been completed successfully, the application will receive a client certificate, which can be used for a communication channel with the SDN controller.


## The process
In a), the common way of accessing the controller from an application is shown. This is usually done by a HTTP, HTTPS or trusted HTTPS connection. To make this connection more trustworthy, additional components were used, which are listed in b):

![Setup](https://cdn.rawgit.com/svartkanin/User-security-guarantees/master/Images/components.svg)

Intel's SGX enclave is used for encryption/decryption of sent/received data. To make the developed system more generic and applicable for different controller types, an nginx server in front of the actual SDN controller was used to perform the client certificate validation. Before an application can start a communication channel with the controller (or nginx), it has to receive a valid certificate, which is distributed by the _Verification Manager_. This manager acts as a orchestrator for the entire attestation/validation process. The _IAS_, Intel Attestation Service, is used for the attestation of the enclaves running on the remote system. It is part of the Intel SGX framework and can be accessed via a REST API. 

### Steps
![Setup](https://cdn.rawgit.com/svartkanin/User-security-guarantees/master/Images/workflow.svg)

The _Verification Manager_ (VM) starts a remote attestation (1) with the remote host during which it contacts the IAS for the Enclave attestation running on the remote host (2). After the remote attestation has finished successfully, the remote host will sent the Linux IMA measurement list encrypted to the VM which validates its integrity. If that has been successful as well, the VM will generate a Key _K_ and a nonce _n1_ which are sent encrypted to the remote host. The remote host calculates the HMAC-SHA512 using _K_ and _n1_ and sends the result back to the VM. It further stores _K_ in a Docker data volume so that it can be accessed by the Application running inside the container later on. 
After the VM has confirmed, that the HMAC received by the remote host is correct, it will start a second remote attestation process with the container application (3). During this attestation it has to access the IAS service once again (4). After the attestation process has been conducted successfully, the VM will generate a second nonce _n2_ and send it to the application. Since the key _K_ has been stored previously in the data volume by the remote host, the application can access _K_ and use it to calculate the HMAC-SHA512 with _K_ and _n2_. The reulsting HMAC is sent back to the VM and if valdiated successfully, it can be determined, that the application is indeed running on the same system as the verified remote host. 
Now the VM will generate a public and private certificate, which are sent to the application. The public certificate is sent to _nginx_ (5) so it can be used for the client certificate validation. 
When the application receives the certificate, it can start a secure TLS connection with the controller (6), which knows that the application is trustworthy due to the performed attestation process. The TLS connection is established from within the SGX enclave and does therefore not leak any secure keys or data!




## Installation
For the system to work properly, it requires the installation of Intel SGX [here](https://github.com/01org/linux-sgx)  and the SGX driver [here](https://github.com/01org/linux-sgx-driver). Please install both in the _/opt_ directory, otherwise changes to each Makefile have to be made manually!
Furthermore, also a developer account for the usage of IAS has to be registered [Developer account](https://software.intel.com/en-us/sgx) . The registration requires the upload of a certificate (can be self-signed for development purposes).Intel will respond with a SPID which is needed to access the REST API of the IAS.

To be able to run all 3 programs, external libraries have to be installed, if they are not present already:
- Google Protocol Buffers (should already be installed with the SGX SDK package) otherwise install libprotobuf-dev, libprotobuf-c0-dev and protobuf-compiler
- ```libboost-thread-dev```, ```libboost-system-dev```
- ```curl```, ```libcurl4-openssl-dev```
- ```libssl```
- ```liblog4cpp5-dev```
	
In addition the mbedtls library with SGX support has to be downloaded from [mbedtls-sgx](https://github.com/bl4ck5un/mbedtls-SGX) and copied into the directory _Application/_.
Then execute:

 ```cd Application/mbedtls-SGX```<br/>
 ```make```

To be able to create SGX enclaves inside a Docker container, patched containers have to be used for now. Such containers can be found here [tozd/docker-sgx](https://github.com/tozd/docker-sgx) or here [aminueza/docker-sgx](https://github.com/aminueza/docker-sgx).

In addition of using the patched containers, the containers have to be run with the ```-v``` parameter
```-v <remote_host_path>:<container_path>```
This will create a Docker data volume so that the Key _K_ can be exchanged between the host and the container application.

All message exchanges between the different componnets are performed over SSL/TLS. For development purposes self-signed certificates were used which can be created with the following command:
```openssl req -x509 -nodes -newkey rsa:4096 -keyout <name>.key -out <name>.crt -days 365```


## Settings
Before running the programs, the ```GeneralSettings.h``` must be modified:
- ```rh_port```: Remote host port on which the server is running
- ```rh_host```: Remote host IP on which the server is running
- ```container_port```: Container port on which the server is running
- ```container_host```: Container IP on which the server is running
- ```measurement_list```: Path to the measurement list
- ```remotehostHashKeyLocation```: Docker data volume path on the remote host
- ```applicationHashKeyLocation```: Docker data volume path on the container
- ```nginx_pub_crt```: Public certificate path for nginx
- ```server_crt```: Certificate file path for the Servers (Remote host and Application the same)
- ```server_key```: Private Key file path for the Servers (Remote host and Application the same)
- ```spid```: SPID provided by Intel when registering developer account
- ```ias_crt```: IAS certificate used when registering developer account
- ```ias_url```: REST API IAS
- ```nginx_client_crts```: File to store certificates for client authentication performed by nginx



## Compiling and running
To compile all 3 programs execute:
```cd VerificationManager```
```make```
```cd ../RemoteHost```
```make SGX_MODE=HW SGX_PRERELEASE=1```
```cd ../Application```
```make SGX_MODE=HW SGX_PRERELEASE=1```

The created programs ```app``` are then located in the folders _VerificationManager_, _RemoteHost_ and _Application_, and can simply be run with ```./app```


