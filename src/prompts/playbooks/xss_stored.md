## XSS Stored Playbook

**STRATEGY:** Find places where user input is saved and displayed to other users (comments, profiles, posts).

### Steps
1. Find comment forms, profile fields, blog posts, or any persistent input
2. Submit XSS payload: `<script>alert('xss')</script>`
3. Navigate away, then return to the page where content displays
4. If JavaScript alert appears on page load → CONFIRMED
5. Try alternative payloads if filtered: `<img src=x onerror=alert(1)>`

### Key Locations to Test
- Comment sections (blogs, products, forums)
- User profile fields (bio, name, website)
- Post/message content
- File upload names
- Review/feedback forms

### Indicators of Success
- Payload executes when page loads (without interaction)
- Alert/dialog appears for any user viewing the page
- Payload persists across sessions

### Common Bypass Techniques
- HTML entities: `&lt;script&gt;` sometimes decoded
- SVG tags: `<svg onload=alert(1)>`
- IMG onerror: `<img src=x onerror=alert(1)>`
- Body onload: `<body onload=alert(1)>`
- Event handlers in attributes
