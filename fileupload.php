<?php
define('_VALID', true);

header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

require 'include/config.paths.php';
require 'include/config.php';
require 'include/config.local.php';
require 'include/sessions.php';
require 'include/function_user.php';

$basedir  = $config['BASE_DIR'];
$targetDir = $config['VDO_DIR'];
$cleanupTargetDir = true;
$maxFileAge = 5 * 3600; // Temp file age in seconds

// --- SECURITY: kræv login (og evt. admin) før upload ---
if (!isset($_SESSION['uid']) || !$_SESSION['uid']) {
    http_response_code(403);
    die('{"jsonrpc" : "2.0", "error" : {"code": 110, "message": "Authentication required."}, "id" : "id"}');
}

// Optional: kræv admin‑rolle hvis kun admins må uploade
/*
$user = VUser::get_profile($_SESSION['uid']);
if ($user['account_type'] != 'admin') {
    http_response_code(403);
    die('{"jsonrpc" : "2.0", "error" : {"code": 111, "message": "Not authorized."}, "id" : "id"}');
}
*/

// Valgfrit referer‑tjek som ekstra lag
$site_url  = $config['BASE_URL'];
$site_url  = parse_url($site_url, PHP_URL_HOST);
$referal_url = isset($_SERVER['HTTP_REFERER']) ? parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) : null;
if ($referal_url && $site_url != $referal_url) {
    die('Invalid Upload!');
}

// Get a file name
if (isset($_REQUEST["name"])) {
    $fileName = $_REQUEST["name"];
} elseif (!empty($_FILES)) {
    $fileName = $_FILES["file"]["name"];
} else {
    $fileName = uniqid("file_");
}

// Clean the fileName for security reasons
$fileName = preg_replace('/[^\w\._]+/', '_', $fileName);

// --- SECURITY: filtype‑whitelist + max size ---
$allowed_ext = array('avi','mpg','mov','asf','mpeg','xvid','divx','3gp','mkv','3gpp','mp4','rmvb','rm','dat','wmv','flv','ogg','ogv','webm');
$ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_ext)) {
    http_response_code(400);
    die('{"jsonrpc" : "2.0", "error" : {"code": 112, "message": "File type not allowed."}, "id" : "id"}');
}

// Optional: begræns filstørrelse (råt eksempel, afhænger af dit setup)
if (!empty($_FILES['file']['size']) && $_FILES['file']['size'] > $config['max_video_size']) {
    http_response_code(400);
    die('{"jsonrpc" : "2.0", "error" : {"code": 113, "message": "File too large."}, "id" : "id"}');
}

// Generér sikkert internt filnavn for temp
$randomName = bin2hex(random_bytes(16)) . '.' . $ext;
$filePath   = $targetDir . DIRECTORY_SEPARATOR . $randomName;

// Chunking might be enabled
$chunk  = isset($_REQUEST["chunk"]) ? intval($_REQUEST["chunk"]) : 0;
$chunks = isset($_REQUEST["chunks"]) ? intval($_REQUEST["chunks"]) : 0;

// Remove old temp files
if ($cleanupTargetDir) {
    if (!is_dir($targetDir) || !$dir = opendir($targetDir)) {
        die('{"jsonrpc" : "2.0", "error" : {"code": 100, "message": "Failed to open temp directory."}, "id" : "id"}');
    }
    while (($file = readdir($dir)) !== false) {
        $tmpfilePath = $targetDir . DIRECTORY_SEPARATOR . $file;
        // If temp file is current file proceed to the next
        if ($tmpfilePath == "{$filePath}.part") {
            continue;
        }
        // Remove temp file if it is older than the max age and is not the current file
        if (preg_match('/\.part$/', $file) && (filemtime($tmpfilePath) < time() - $maxFileAge)) {
            @unlink($tmpfilePath);
        }
    }
    closedir($dir);
}

if (isset($_SERVER["HTTP_CONTENT_TYPE"])) {
    $contentType = $_SERVER["HTTP_CONTENT_TYPE"];
}
if (isset($_SERVER["CONTENT_TYPE"])) {
    $contentType = $_SERVER["CONTENT_TYPE"];
}

// Handle non multipart uploads older WebKit versions didn't support multipart in HTML5
if (strpos($contentType ?? '', "multipart") !== false) {
    if (isset($_FILES['file']['tmp_name']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
        // Open temp file
        if (!$out = @fopen("{$filePath}.part", $chunks ? "ab" : "wb")) {
            die('{"jsonrpc" : "2.0", "error" : {"code": 102, "message": "Failed to open output stream."}, "id" : "id"}');
        }
        if (!empty($_FILES)) {
            if ($_FILES["file"]["error"] || !is_uploaded_file($_FILES["file"]["tmp_name"])) {
                die('{"jsonrpc" : "2.0", "error" : {"code": 103, "message": "Failed to move uploaded file."}, "id" : "id"}');
            }
            // Read binary input stream and append it to temp file
            if (!$in = @fopen($_FILES["file"]["tmp_name"], "rb")) {
                die('{"jsonrpc" : "2.0", "error" : {"code": 101, "message": "Failed to open input stream."}, "id" : "id"}');
            }
        } else {
            if (!$in = @fopen("php://input", "rb")) {
                die('{"jsonrpc" : "2.0", "error" : {"code": 101, "message": "Failed to open input stream."}, "id" : "id"}');
            }
        }
        while ($buff = fread($in, 4096)) {
            fwrite($out, $buff);
        }
        @fclose($out);
        @fclose($in);
    } else {
        die('{"jsonrpc" : "2.0", "error" : {"code": 103, "message": "Failed to move uploaded file."}, "id" : "id"}');
    }
} else {
    // Open temp file
    $out = fopen("{$filePath}.part", $chunk == 0 ? "wb" : "ab");
    if ($out) {
        // Read binary input stream and append it to temp file
        $in = fopen("php://input", "rb");
        if ($in) {
            while ($buff = fread($in, 4096)) {
                fwrite($out, $buff);
            }
        }
        fclose($in);
        fclose($out);
    }
}

// Check if file has been uploaded
if (!$chunks || $chunk == $chunks - 1) {
    // Strip the temp .part suffix off
    rename("{$filePath}.part", $filePath);

    if (isset($_REQUEST['id'])) {
        $safeId = preg_replace('/[^\w\-]/', '_', $_REQUEST['id']);
        $extension = pathinfo($filePath, PATHINFO_EXTENSION);
        $dest = $targetDir . '/' . $safeId . '.' . $extension;
        if (!@rename($filePath, $dest)) {
            // Hvis rename fejler, behold temp‑filen men eksponér ikke dens navn
        }
    }
}

die('{"jsonrpc" : "2.0", "result" : null, "id" : "id"}');
?>
