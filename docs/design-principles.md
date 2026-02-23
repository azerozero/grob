# Grob Design Principles

Grob's design philosophy is **"Simplify complex AI routing"**.

Our goal is to minimize the complexity developers face when using multiple AI providers, making every aspect of configuration, monitoring, and management intuitive.

---

## 1. Our Design Philosophy

### Simplicity First
- Hide complex AI routing logic from users, exposing only essential configurations.
- Aim for "minimum steps to desired outcome" in both CLI and Admin UI.
- Keep technical complexity internal, user experience simple.

### Developer-First Experience
- Use terminology and structures familiar to developers.
- Share the same mental model between config files (TOML) and UI.
- Error messages clearly communicate "what went wrong" and "how to fix it".

### Performance as UX
- ~5MB memory, <1ms routing overhead is not just performance metrics—it's user experience.
- Fast responses build trust, lightweight resource usage simplifies deployment.

---

## 2. Admin UI Product Principles

### Value first, cost later
**Show users the value of configuration first, expose complex settings later.**

#### Examples
- ❌ Bad: Immediately require API key, Base URL, and type on one screen when adding a Provider
- ✅ Good: Step-by-step progression: "Which Provider?" → Select type → Name it → Enter API key

#### Checkpoints
- [ ] When adding a new feature, can users understand "why they need to do this" first?
- [ ] Can complex options be collapsed under "Advanced settings"?
- [ ] Are required vs optional fields clearly distinguished?

---

### Easy to answer
**Users should instantly understand what to select and what to input on each screen.**

#### Examples
- ❌ Bad: Abstract labels like "Model mappings configuration"
- ✅ Good: "Select Provider" → "Actual model name" → "Choose which Provider to use for claude-sonnet-4"

#### Checkpoints
- [ ] Does each input field have placeholder or helper text?
- [ ] Are choices (radio, select) limited to 3-5 options?
- [ ] Do error messages explain "what's wrong and how to fix it"?

---

### One thing per one page
**Each screen handles only one purpose.**

#### Examples
- ✅ Overview page: View overall status only
- ✅ Provider management page: View, add, edit, delete Providers only
- ✅ Model management page: View, add, edit, delete Models only
- ✅ Router settings page: Configure routing rules only

#### Checkpoints
- [ ] Can you describe this page's core purpose in one sentence?
- [ ] Does the page title (h1) accurately reflect user intent?
- [ ] Do multiple features on the page not compete with each other?

---

## 3. UX Writing Principles

### Concise = Remove meaningless words
- ❌ "We are showing you a list of currently configured Providers"
- ✅ "Provider list"

### Technical but not jargon
- ✅ "Provider" - Familiar term to developers
- ✅ "Model mapping" - Clear meaning
- ❌ "Inference endpoint configuration" - Unnecessarily complex

### Action-oriented labels
- ✅ "Add Provider"
- ✅ "Edit Model"
- ❌ "Add" (unclear what's being added)

---

## 4. Metrics and Monitoring

### Performance metrics as UX feedback
- Display routing overhead and memory usage in Admin UI in real-time
- Users can immediately see "how efficient my configuration is"

### Error tracking
- Track error rate and response time per Provider
- Immediately identify and respond to problematic Providers

### Checkpoints
- [ ] Are important metrics displayed numerically?
- [ ] Can problem situations be immediately noticed via red/warning icons?
- [ ] Can statistics be viewed by time period and Provider?

---

## 5. Accessibility and Universal UX

### Keyboard navigation
- All features must be accessible via keyboard only
- Tab order must be logical
- Focus state must be clearly visible

### Semantic HTML
- Buttons are `<button>`, links are `<a>`, forms are `<form>`
- Screen readers must understand page structure

### Checkpoints
- [ ] Can all tasks be completed with just Tab + Enter, without a mouse?
- [ ] Is information not conveyed by color alone? (colorblind support)
- [ ] Are error messages readable by screen readers?

---

## 6. Interaction and Feedback

### Immediate feedback
- Button click → Immediately show loading state
- Form submit → Immediately show success/failure notification
- Config change → Show "unsaved changes" indicator

### Progressive disclosure
- Show basic settings first, expose rest via "Advanced settings" button
- Provider addition progresses step-by-step with ability to go back

### Checkpoints
- [ ] Is there immediate feedback for every action?
- [ ] Are users not left waiting during loading?
- [ ] Is Undo/cancel provided for destructive actions?

---

## 7. Tools and Automation

### Configuration validation
- Validate TOML config file before saving
- Invalid config won't save and provides clear error message

### Smart defaults
- Provide reasonable defaults when adding new Provider
- Auto-assign Model mapping priorities as 1, 2, 3...

### Development efficiency
- Test config changes without server restart via hot reload
- One-click "Save & Restart" from Admin UI after config changes

---

## 8. Practical Checklist for Developers

### Before adding new features
- [ ] Is this feature designed with one page/one purpose?
- [ ] Does it show value to users first?
- [ ] Are questions and choices clear?

### When writing UI components
- [ ] Have you removed meaningless words from all text?
- [ ] Is it usable with keyboard only?
- [ ] Are error and loading states clear?

### When designing forms
- [ ] Are required fields clearly marked?
- [ ] Does each field have placeholder/helper text?
- [ ] Do validation checks (duplicate, format) happen immediately?

### When handling errors
- [ ] Does the error message explain "what" went wrong?
- [ ] Does the error message explain "how" to fix it?
- [ ] Is the error visible to users?

### When optimizing performance
- [ ] Does the page load in under 2 seconds?
- [ ] Does it respond immediately to user actions?
- [ ] Have unnecessary network requests been eliminated?

---

## Example: Provider Addition Flow

### Before (❌ Everything on one screen)
```
Add Provider
- Name: [        ]
- Type: [Select▼]
- API Key: [        ]
- Base URL: [        ]
- Model list: [        ]
- Enabled: [v]
[Add]
```

### After (✅ Step-by-step)
```
Step 1: Which Provider would you like to add?
○ Anthropic  ○ OpenAI  ○ OpenRouter
(Large card format for selection)

Step 2: Name your Provider
Name: [anthropic-main]
(This name will be used to reference it in Model mappings)

Step 3: Enter your API key
API Key: [sk-ant-...]
(You can get this from the provider's website)

Step 4: Done!
✓ anthropic-main Provider has been added
Now go to the Model tab to add models using this Provider
```

---

## References

### Toss UX Design Principles (Inspiration)
- [Simplicity Behind](https://toss.tech/article/simplicity_behind)
- [Simplicity 24](https://toss.im/tossfeed/article/simplicity24)
- [Toss Tech Blog](https://toss.tech)
- [Value First, Cost Later](https://toss.tech/article/value-first-cost-later)
- [Insurance Claim Process](https://toss.tech/article/insurance-claim-process)
- [Design Motivation](https://toss.tech/article/design-motivation)
- [8 Writing Principles of Toss](https://toss.tech/article/8-writing-principles-of-toss)

### Project Documentation
- [URL-based State Management](./url-state-management.md) - Our navigation pattern
- [LocalStorage-based State Management](./localstorage-state-management.md) - Our state management pattern
