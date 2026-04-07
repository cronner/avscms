<?php
/**
 * CSRF Protection Class
 * Prevents Cross-Site Request Forgery attacks
 */

class CSRF
{
    private static $token_name = 'csrf_token';
    
    /**
     * Generate a new CSRF token and store it in session
     * @return string The generated token
     */
    public static function generateToken()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Generate cryptographically secure random token
        $token = bin2hex(random_bytes(32));
        $_SESSION[self::$token_name] = $token;
        
        return $token;
    }
    
    /**
     * Get the current CSRF token from session, or generate a new one
     * @return string The CSRF token
     */
    public static function getToken()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        if (!isset($_SESSION[self::$token_name])) {
            return self::generateToken();
        }
        
        return $_SESSION[self::$token_name];
    }
    
    /**
     * Verify a submitted CSRF token against the session token
     * @param string|null $submitted_token The token to verify
     * @return bool True if valid, false otherwise
     */
    public static function verify($submitted_token = null)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // If no token provided, try POST data
        if ($submitted_token === null) {
            $submitted_token = isset($_POST[self::$token_name]) ? $_POST[self::$token_name] : null;
            
            // Also check headers for AJAX requests
            if ($submitted_token === null && isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
                $submitted_token = $_SERVER['HTTP_X_CSRF_TOKEN'];
            }
        }
        
        // No token to verify
        if ($submitted_token === null || empty($submitted_token)) {
            return false;
        }
        
        // No token in session
        if (!isset($_SESSION[self::$token_name])) {
            return false;
        }
        
        // Use timing-safe comparison
        if (!hash_equals($_SESSION[self::$token_name], $submitted_token)) {
            return false;
        }
        
        // Token is valid - regenerate to prevent reuse (optional but recommended)
        self::generateToken();
        
        return true;
    }
    
    /**
     * Get the HTML input field for forms
     * @return string HTML hidden input field
     */
    public static function getField()
    {
        $token = self::getToken();
        return '<input type="hidden" name="' . self::$token_name . '" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
    }
    
    /**
     * Get token as meta tag for AJAX requests
     * @return string HTML meta tag
     */
    public static function getMetaTag()
    {
        $token = self::getToken();
        return '<meta name="csrf-token" content="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
    }
    
    /**
     * Regenerate token (useful after successful form submission)
     * @return string New token
     */
    public static function regenerate()
    {
        return self::generateToken();
    }
}
?>
