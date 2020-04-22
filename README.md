Installation
------------

1. Install [docker](https://docs.docker.com/engine/installation/) if you don't
   already have it.

2. Clone the repository to local 

    ```
    git clone https://github.com/DINGDAMU/P4DDoS.git    
    ```

3. ```
    cd P4DDoS
   ```

4. If you want, put the `p4app` script somewhere in your path. For example:

    ```
    cp p4app /usr/local/bin
    ```
    I have already modified the default docker image to **dingdamu/p4app-ddos:nwhhd**, so `p4app` script can be used directly.

P4DDoS
--------------

1.  ```
    ./p4app run p4ddos.p4app 
    ```
    After this step you'll see the terminal of **mininet**
2. Forwarding at least 1 packets in **mininet**

   ```
    pingall
    pingall
   ```
or 
   ```
    h1 ping h2 -c 12 -i 0.1
   ```



3. Enter p4ddos.p4app folder
   ```
    cd p4ddos.p4app 
   ```
4. Check the result by reading the register
   ```
    ./read_registers1.sh
    ./read_registers2.sh
    ./read_registers3.sh
   ```
 
 Register `thresholdReg[0]` is threshold for normalized entropy

 Register `ewmaReg[0]` is the current expoenential weighter moving average of normalized entropy.

 Note that all values are amplified 1024 times

