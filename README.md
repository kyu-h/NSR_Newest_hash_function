# NSR_Newest_hash_function
This project is for matched reference log with NSR.
We will not develope SHA3 base code. We just get original code from Keccak Team.
If we have some time, we will change that base code on our own. (If possible..)

1. We will find SHA3 hash values and matched that values with NSR due to April 27. --> Clear(April 25) <br>
 ->Can check hash values result in this web site: https://leventozturk.com/engineering/sha3/ <br>
2. Make a HMAC which is SHA3 version due to May 4. --> Clear(May 14) <br>
 ->Can check HMAC hash values result in this web site: http://www.wolfgang-ehrhardt.de/hmac-sha3-testvectors.html <br>
3. Make a Hash_DRBG due to MAY 16. <br>
 ->Reference site of how to set DRBG: https://github.com/Chronic-Dev/libgcrypt <br>
 ->Reference site of how to set DRBG: https://tls.mbed.org/ctr-drbg-source-code <br>
 ->TTAK.KO-12.0190: http://committee.tta.or.kr/data/standard_view.jsp?nowPage=3&pk_num=TTAK.KO-12.0190&commit_code=TC5 <br>
 ->How to install mbed TLS: https://www.lesstif.com/pages/viewpage.action?pageId=29590494 <br>
4. Make a HMAC_DRBG due to MAY 23.
5. Make a PBKDF due to MAY 30.
6. Make a HMAC_KDF due to June 20.

<hr>
Every package have test text input file seems like SHA3-224.txt or HMAC_SHA3-224.txt. <br>
Output file which is test result of the input files is SHA3-224_rsp.txt or HMAC_SHA3-224_rsp.txt <br>
So, If you want to check input files and output files, just go test folder (every package have different name. so if some folder have only text file it might be test folder) and check above 2 sentences.

<hr>

<table style="width:100%">
  <tr>
    <th rowspan="2">
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

