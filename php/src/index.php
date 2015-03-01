<?php
require_once 'limonade/lib/limonade.php';

function configure() {
  option('base_uri', '/');
  option('session', 'isu4_qualifier_session');

  $host = getenv('ISU4_DB_HOST') ?: 'localhost';
  $port = getenv('ISU4_DB_PORT') ?: 3306;
  $dbname = getenv('ISU4_DB_NAME') ?: 'isu4_qualifier';
  $username = getenv('ISU4_DB_USER') ?: 'root';
  $password = getenv('ISU4_DB_PASSWORD');
  $db = null;
  $redis = null;
  try {
    $db = new PDO(
      'mysql:host=' . $host . ';port=' . $port. ';dbname=' . $dbname,
      $username,
      $password,
      [ PDO::ATTR_PERSISTENT => true,
        PDO::MYSQL_ATTR_INIT_COMMAND => 'SET CHARACTER SET `utf8`',
      ]
    );

    $redis = new Redis();
    $redis->connect("127.0.0.1", 6379);
    
  } catch (PDOException $e) {
    halt("Connection faild: $e");
  }
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  option('db_conn', $db);
  option('redis_conn', $redis);

  $config = [
    'user_lock_threshold' => getenv('ISU4_USER_LOCK_THRESHOLD') ?: 3,
    'ip_ban_threshold' => getenv('ISU4_IP_BAN_THRESHOLD') ?: 10
  ];
  option('config', $config);
}

function uri_for($path) {
  $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?: $_SERVER['HTTP_HOST'];
  return 'http://' . $host . $path;
}

function get($key) {
  return set($key);
}

function before() {
  layout('base.html.php');
}

function calculate_password_hash($password, $salt) {
  return hash('sha256', $password . ':' . $salt);
}

function redis_key_user($user) {
    return "isu4:user:" . $user['login'];
}

function redis_key_last($user) {
    return "isu4:last:" . $user['login'];
}

function redis_key_nextlast($user=["id" => "*"]) {
    return "isu4:nextlast:" . $user['login'];
}

function redis_key_ip($ip) {
    return "isu4:ip:". $ip;
}



function login_log($succeeded, $login, $user=null) {

    $redis = option('redis_conn');
    $kuser = empty($user) ? null : redis_key_user($user);
    $kip   = redis_key_ip($_SERVER['REMOTE_ADDR']);

    if ($succeeded) {
        $klast = redis_key_last($user);
        $knextlast = redis_key_nextlast($user);

        $redis->set($kip, 0);
        $redis->set($kuser, 0);

        if ($redis->exists($knextlast)) {
            $reids->rename($knextlast, $klast);
            $redis->hMset($knextlast, array('login' => $login, 'ip' => $_SERVER['REMOTE_ADDR'], 'at' => date(DATE_ATOM)));
        } else {
            $redis->hMset($knextlast, array('login' => $login, 'ip' => $_SERVER['REMOTE_ADDR'], 'at' => date(DATE_ATOM)));
        }
    } else {
        $redis->incr($kip);
        $redis->incr($kuser);
    }
}

function user_locked($user) {
    if (empty($user)) { return false; }
    $redis = option('redis_conn');
    $failures = (int)$redis->get(redis_key_user($user));

    $config = option('config');
    return $config['user_lock_threshold'] <= $failures;
}


function ip_banned() {
    $redis = option('redis_conn');
    $failures = (int)$redis->get(redis_key_ip($_SERVER['REMOTE_ADDR']));
    $config = option('config');
    error_log(print_r($failures, true), 3, "/tmp/php.log");  // /tmp/php.logに記述する
    error_log("\r\n", 3, "/tmp/php.log");  // /tmp/php.logに記述する
    return $config['ip_ban_threshold'] <= $failures;
}

function attempt_login($login, $password) {
  $db = option('db_conn');

  $stmt = $db->prepare('SELECT * FROM users WHERE login = :login');
  $stmt->bindValue(':login', $login);
  $stmt->execute();
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

    error_log(ip_banned(), 3, "/tmp/php.log");  // /tmp/php.logに記述する
  if (ip_banned()) {
    login_log(false, $login, $user);
    return ['error' => 'banned'];
  }

  if (user_locked($user)) {
    login_log(false, $login, $user);
    return ['error' => 'locked'];
  }

  if (!empty($user) && calculate_password_hash($password, $user['salt']) == $user['password_hash']) {
   
    error_log(print_r($password, true), 3, "/tmp/php.log");  // /tmp/php.logに記述する
    login_log(true, $login, $user);
    return ['user' => $user];
  }
  elseif (!empty($user)) {
    login_log(false, $login, $user);
    return ['error' => 'wrong_password'];
  }
  else {
    login_log(false, $login);
    return ['error' => 'wrong_login'];
  }
}

function current_user() {
  if (empty($_SESSION['user_id'])) {
    return null;
  }

  $db = option('db_conn');

  $stmt = $db->prepare('SELECT * FROM users WHERE id = :id');
  $stmt->bindValue(':id', $_SESSION['user_id']);
  $stmt->execute();
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  if (empty($user)) {
    unset($_SESSION['user_id']);
    return null;
  }

  return $user;
}

function last_login() {
	$user = current_user();
	if (empty($user)) {
		return null;
	}
	$redis = option('redis_conn');
	return $redis->hGetAll(redis_key_last($user)) || $redis->hGetAll(redis_key_nextlast($user));
}

function banned_ips() {
   $threshold = option('config')['ip_ban_threshold'];
   $ips = [];

	 $redis = option('redis_conn');
	 foreach($redis->keys('isu4:ip:*') as $key){
			 $failures = (int)$redis->get($key);
			 if($threshold <= $failures) {
					 array_push($ips, $key);
			 }
	 }
	 return $ips;
}

function locked_users() {
		$threshold = option('config')['user_lock_threshold'];
		$user_ids = [];

	 $redis = option('redis_conn');
	 foreach($redis->keys('isu4:user:*') as $key){
			 $failures = (int)$redis->get($key);
			 if($threshold <= $failures) {
					 array_push($user_ids, $key);
			 }
	 }
	 return $user_ids;
}

dispatch_get('/', function() {
  return html('index.html.php');
});

dispatch_post('/login', function() {
  $result = attempt_login($_POST['login'], $_POST['password']);
  if (!empty($result['user'])) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $result['user']['id'];
    return redirect_to('/mypage');
  }
  else {
    switch($result['error']) {
      case 'locked':
        flash('notice', 'This account is locked.');
        break;
      case 'banned':
        flash('notice', "You're banned.");
        break;
      default:
        flash('notice', 'Wrong username or password');
        break;
    }
    return redirect_to('/');
  }
});

dispatch_get('/mypage', function() {
  $user = current_user();

  if (empty($user)) {
    flash('notice', 'You must be logged in');
    return redirect_to('/');
  }
  else {
    set('user', $user);
    set('last_login', last_login());
    return html('mypage.html.php');
  }
});

dispatch_get('/report', function() {
  return json_encode([
    'banned_ips' => banned_ips(),
    'locked_users' => locked_users()
  ]);
});

run();
