<?php
defined('_VALID') or die('Restricted Access!');

class Remember
{
    public static function check()
    {    
        if (!isset($_SESSION['uid']) && isset($_COOKIE['remember'])) {
            $browser    = (isset($_SERVER['HTTP_USER_AGENT'])) ? sha1($_SERVER['HTTP_USER_AGENT']) : NULL;
            $ip         = (isset($_SERVER['REMOTE_ADDR']) && ip2long($_SERVER['REMOTE_ADDR'])) ? ip2long($_SERVER['REMOTE_ADDR']) : NULL;
            
            // New secure token-based remember me
            $cookie_data = @json_decode(base64_decode($_COOKIE['remember']), true);
            
            if ($cookie_data && isset($cookie_data['username']) && isset($cookie_data['token']) && isset($cookie_data['selector'])) {
                global $conn;
                
                $uid = intval($cookie_data['selector']);
                $token = $cookie_data['token'];
                $token_hash = hash('sha256', $token);
                
                // Verify token in database
                $sql = "SELECT rt.UID, s.username, s.email, s.emailverified, s.photo, s.fname, s.logintime
                        FROM remember_tokens rt
                        INNER JOIN signup s ON rt.UID = s.UID
                        WHERE rt.UID = " . $uid . "
                        AND rt.token = " . $conn->qStr($token_hash) . "
                        AND rt.expiry > " . time() . "
                        LIMIT 1";
                
                $rs = $conn->execute($sql);
                
                if ($conn->Affected_Rows() === 1) {
                    $user = $rs->getrows();
                    $yesterday  = time() - 86400;
                    $sql_add    = NULL;
                    if ( intval($user['0']['logintime']) < $yesterday ) {
                        $sql_add = ", points = points+5";
                    }
                    $sql  = "UPDATE signup SET logintime = '" .time(). "'" .$sql_add. " WHERE username = " .$conn->qStr($user['0']['username']). " LIMIT 1";
                    $conn->execute($sql);
                    $_SESSION['uid']            = intval($user['0']['UID']);
                    $_SESSION['username']       = $user['0']['username'];
                    $_SESSION['email']          = $user['0']['email'];
                    $_SESSION['emailverified']  = $user['0']['emailverified'];
                    $_SESSION['photo']          = $user['0']['photo'];
                    $_SESSION['fname']          = $user['0']['fname'];
                    $_SESSION['message']        = 'Welcome ' .$user['0']['username']. '!';
                    
                    // Rotate token for security
                    self::set($user['0']['username'], $uid);
                    
                    // Delete old token
                    $conn->execute("DELETE FROM remember_tokens WHERE UID = " . $uid . " AND token = " . $conn->qStr($token_hash));
                } else {
                    // Invalid token, clear cookie
                    self::del();
                }
            }
            // Legacy format no longer supported for security reasons
        }
    }
    
    public static function set($username, $uid = null)
    {
        // Generate new secure token
        $remember_token = bin2hex(random_bytes(32));
        $token_hash = hash('sha256', $remember_token);
        $expiry = time() + (30 * 24 * 60 * 60); // 30 days
        
        global $conn;
        
        // If uid not provided, look it up
        if ($uid === null) {
            $sql = "SELECT UID FROM signup WHERE username = " . $conn->qStr($username) . " LIMIT 1";
            $rs = $conn->execute($sql);
            if ($conn->Affected_Rows() === 1) {
                $user = $rs->getrows();
                $uid = $user['0']['UID'];
            } else {
                return false;
            }
        }
        
        // Store new token
        $sql_token = "INSERT INTO remember_tokens (UID, token, expiry) VALUES (" 
                   . $uid . ", " . $conn->qStr($token_hash) . ", " . $expiry . ")";
        $conn->execute($sql_token);
        
        // Set secure cookie
        $remember_data = base64_encode(json_encode([
            'username' => $username,
            'token' => $remember_token,
            'selector' => $uid
        ]));
        setcookie('remember', $remember_data, $expiry, '/', '', false, true); // httponly=true
        
        return true;
    }
    
    public static function del()
    {
        // Clear cookie
        setcookie('remember', '', time()-60*60*24*100, '/', '', false, true);
        
        // Also try to clean up database tokens if we have cookie data
        if (isset($_COOKIE['remember'])) {
            $cookie_data = @json_decode(base64_decode($_COOKIE['remember']), true);
            if ($cookie_data && isset($cookie_data['selector'])) {
                global $conn;
                $uid = intval($cookie_data['selector']);
                $conn->execute("DELETE FROM remember_tokens WHERE UID = " . $uid);
            }
        }
    }
}
?>