<?php
define('_VALID', true);
require 'include/config.php';
require 'include/function_global.php';
require 'include/function_smarty.php';

if ( isset($_POST['submit_login']) ) {
    require 'classes/filter.class.php';
    $filter     = new VFilter();
    $username   = $filter->get('username');
    $password   = $filter->get('password');
    $current_url= $filter->get('current_url');	
    
    if ( $username == '' || $password == '' ) {
        $errors[] = $lang['login.empty'];
    }
    
    if ( !$errors ) {
        $sql    = "SELECT UID, email, pwd, emailverified, photo, fname, logintime, gender,premium
                   FROM signup WHERE username = " .$conn->qStr($username). " LIMIT 1";
        $rs     = $conn->execute($sql);
        if ( $conn->Affected_Rows() == 1 ) {
            $user   = $rs->getrows();
            
            // Check password using modern secure methods
            // Support both legacy MD5 and new password_hash format
            $password_valid = false;
            
            // Check if stored hash is in new format (starts with $2y$, $2a$, $P$, etc.)
            if (strlen($user['0']['pwd']) >= 60 && substr($user['0']['pwd'], 0, 4) !== 'md5:') {
                // New format: use password_verify
                if (password_verify($password, $user['0']['pwd'])) {
                    $password_valid = true;
                    
                    // Rehash if needed (algorithm upgrade)
                    if (password_needs_rehash($user['0']['pwd'], PASSWORD_ARGON2ID)) {
                        $new_hash = password_hash($password, PASSWORD_ARGON2ID);
                        $update_sql = "UPDATE signup SET pwd = " .$conn->qStr($new_hash). " WHERE UID = " .$user['0']['UID']. " LIMIT 1";
                        $conn->execute($update_sql);
                    }
                }
            } else {
                // Legacy format: check MD5 (backward compatibility)
                $md5_password = md5($password);
                $stored_hash = $user['0']['pwd'];
                
                // Handle both old raw MD5 and prefixed format
                if (substr($stored_hash, 0, 4) === 'md5:') {
                    $stored_hash = substr($stored_hash, 4);
                }
                
                if (hash_equals($stored_hash, $md5_password)) {
                    $password_valid = true;
                    
                    // Upgrade to secure hashing
                    $new_hash = password_hash($password, PASSWORD_ARGON2ID);
                    $update_sql = "UPDATE signup SET pwd = " .$conn->qStr($new_hash). " WHERE UID = " .$user['0']['UID']. " LIMIT 1";
                    $conn->execute($update_sql);
                }
            }
            
            if ($user['0']['emailverified'] == 'no') { 
                $errors[] = 'Please verify your email to login!';
            } elseif ($password_valid) {
                $yesterday  = time() - 86400;
                $sql_add    = NULL;
                if ( intval($user['0']['logintime']) < $yesterday ) {
                    $sql_add = ", points = points+5";
                }
            
                $sql    = "UPDATE signup SET logintime = '" .time(). "'" .$sql_add. " WHERE username = " .$conn->qStr($username). " LIMIT 1";
                $conn->execute($sql);
                $_SESSION['uid']            = $user['0']['UID'];
				if ($user['0']['premium'] == '1') {
					$_SESSION['uid_premium'] = 1;
				}
                $_SESSION['username']       = $username;
                $_SESSION['email']          = $user['0']['email'];
                $_SESSION['emailverified']  = $user['0']['emailverified'];
                $_SESSION['photo']          = $user['0']['photo'];
                $_SESSION['fname']          = $user['0']['fname'];
                $_SESSION['gender']         = $user['0']['gender'];
                $_SESSION['message']        = $lang['login.welcome'] .$username. '!';
                
                if (isset($_POST['login_remember']) && $config['user_remember'] == '1') {
                    // Generate secure random token for remember-me instead of storing password hash
                    $remember_token = bin2hex(random_bytes(32));
                    
                    // Store token in database
                    $token_hash = hash('sha256', $remember_token);
                    $expiry = time() + (30 * 24 * 60 * 60); // 30 days
                    
                    $sql_token = "INSERT INTO remember_tokens (UID, token, expiry) VALUES (" 
                               . $user['0']['UID'] . ", " . $conn->qStr($token_hash) . ", " . $expiry . ")";
                    $conn->execute($sql_token);
                    
                    // Set cookie with token and username only
                    $remember_data = base64_encode(json_encode([
                        'username' => $username,
                        'token' => $remember_token,
                        'selector' => $user['0']['UID']
                    ]));
                    setcookie('remember', $remember_data, $expiry, '/', '', false, true); // httponly=true
                }
                    
				if (strpos(strtolower($current_url), 'signup') !== false || strpos(strtolower($current_url), 'login') !== false) {
					$current_url = '';
				}
                $_URL = $config['BASE_URL'].$current_url; 
                VRedirect::go($_URL);
            } else {
                $errors[] = $lang['login.invalid'];
            }
        }
        } else {
            $errors[] = $lang['login.invalid'];
        }
    }
}

$smarty->assign('errors',$errors);
$smarty->assign('messages',$messages);
$smarty->assign('menu', 'home');
$smarty->assign('submenu', '');
$smarty->assign('self_title', $seo['login_title']);
$smarty->assign('self_description', $seo['login_desc']);
$smarty->assign('self_keywords', $seo['login_keywords']);
$smarty->loadFilter('output', 'trimwhitespace');
$smarty->display('header.tpl');
$smarty->display('login.tpl');
$smarty->display('footer.tpl');
?>
