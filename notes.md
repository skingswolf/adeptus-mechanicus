# Hacking Notes!
  - [Network Requests](#network-requests)
  - [Javascript obsfucation](#javascript-obsfucation)

## Network Requests

* `curl http:/SERVER_IP:PORT/foo.php -X POST -d "payload=value"`

## Javascript obsfucation

Packing, ciphers, base64/hex/rot encoding

* A packer obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the (p,a,c,k,e,d) function to re-build the original code during execution. 
  - The (p,a,c,k,e,d) can be different from one packer to another. 
  - However, it usually contains a certain order in which the words and symbols of the original code were packed to know how to order them during execution.
* `eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))`
* [Obsfucator Tool](https://beautifytools.com/javascript-obfuscator.php)
* [A More Advanced Obsfucator Tool](https://obfuscator.io)
* [JSF - Really cool tool](http://www.jsfuck.com/)
* [JJ Encode](https://utf-8.jp/public/jjencode.html)
* [AA Encode](https://utf-8.jp/public/aaencode.html)

* [JSNice - code formatter tool](http://www.jsnice.org/)

* Base 64
  - Encode - `echo https://www.foo.com/ | base64`
  - Decode - `echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`

* Hex
  - Encode - `echo https://www.foo.com/ | xxd -p`
  - Decode - `echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`

* Ceaser/Rot13
  - Caesar cipher shifts each letter by a fixed number. E.g. Rot13 shifts letters by 13 places
  - Encode - `echo https://www.foo.com/ |  tr 'A-Za-z' 'N-ZA-Mn-za-m'`
  - Decode - `echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`

* [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)




| Syntax | Description |
| ----------- | ----------- |
| Header | Title |
| Paragraph | Text |