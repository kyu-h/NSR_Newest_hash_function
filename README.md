# NSR_Newest_hash_function
This project is for matched reference log with NSR.
We will not develope SHA3 base code. We just get original code from Keccak Team.
If we have some time, we will change that base code on our own. (If possible..)

1. We will find SHA3 hash values and matched that values with NSR due to April 27. --> Clear(April 25) <br>
 ->Can check hash values result in this web site: https://leventozturk.com/engineering/sha3/ <br>
 <a href="https://github.com/kyu-h/NSR_Newest_hash_function/tree/master/SHA3" target="_blank">SHA3 stand alone version</a> <br>
 <a href="https://github.com/kyu-h/NSR_Newest_hash_function/tree/master/SHA3_Devide_ver" target="_blank">SHA3 devide version(init, update, final)</a> <br>
2. Make a HMAC which is SHA3 version due to May 4. --> Clear(May 14) <br>
 ->Can check HMAC hash values result in this web site: http://www.wolfgang-ehrhardt.de/hmac-sha3-testvectors.html <br>
 <a href="https://github.com/kyu-h/NSR_Newest_hash_function/tree/master/SHA3_HMAC" target="_blank">SHA3 HMAC(Based SHA3 devide version)</a> <br>
3. Make a Hash_DRBG due to MAY 16. --> Clear(June 11)<br>
 ->Reference site of how to set DRBG: https://github.com/Chronic-Dev/libgcrypt <br>
 ->Reference site of how to set DRBG: https://tls.mbed.org/ctr-drbg-source-code <br>
 ->TTAK.KO-12.0190: http://committee.tta.or.kr/data/standard_view.jsp?nowPage=3&pk_num=TTAK.KO-12.0190&commit_code=TC5 <br>
 ->How to install mbed TLS: https://www.lesstif.com/pages/viewpage.action?pageId=29590494 <br>
 ->Recommend to use this web site because TTAK.KO-12.0190 is not perfectly matched which has some bugs: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90a.pdf <br>
  <a href="https://github.com/kyu-h/NSR_Newest_hash_function/tree/master/SHA3_DRBG(window_ver)" target="_blank">SHA3 DRBG(Based SHA3 stand alone version)</a> <br>
4. Make a HMAC_DRBG due to MAY 23. <br> --> Clear(June 18)<br>
->Reference site HMAC_DRBG: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90a.pdf <br>
<a href="https://github.com/kyu-h/NSR_Newest_hash_function/tree/master/SHA3_HMAC_DRBG" target="_blank">SHA3 HMAC DRBG(Based SHA3 HMAC)</a> <br>
5. Make a PBKDF due to MAY 30. <br>
->Reference site PBKDF: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf <br>
6. Make a HMAC_KDF due to June 20. <br>

<hr>
Every package have test text input file seems like SHA3-224.txt or HMAC_SHA3-224.txt. <br>
Output file which is test result of the input files is SHA3-224_rsp.txt or HMAC_SHA3-224_rsp.txt <br>
So, If you want to check input files and output files, just go test folder (every package have different name. so if some folder have only text file it might be test folder) and check above 2 sentences.

<hr>

<table style="width:100%">
  <tr>
    <th rowspan="3">
    OS: Window<br>
    Compiler: MinGW<br>
    IDE: Eclipse<br></th>
    <td>
    SHA3 hash values<br>
    </td>
  </tr>
  <tr>
    <td>SHA3_HMAC</td>
  </tr>
 <tr>
    <td>SHA3_DRBG</td>
  </tr>
</table>
<br>

<table style="width:100%">
  <tr>
    <th rowspan="2">
    OS: Linux<br>
    Compiler: Linux<br>
    IDE: Eclipse<br></th>
    <td>
    SHA3_DRBG<br>
    </td>
  </tr>
  <tr>
    <td>SHA3_HMAC_DRBG</td>
  </tr>
</table>

