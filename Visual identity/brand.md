# Prosze: Brand Guidelines

> Keep what’s yours.

Prosze is a local privacy shield: it swaps secrets, names and personal data in your text for placeholders before the text goes to an AI or another command, then swaps the real values back into the reply.

## 1. Brand idea

Prosze is the cloakroom for your text. You hand over what you’re carrying, the attendant keeps the real thing, you get a numbered ticket to pass along, and when the answer returns you get your things back exactly as they were. The placeholder `[[PERSON_1]]` is that ticket, and the identity is built from it: a paper claim ticket with a tear-off perforation and one stamp-red bar, the redacted part.

The name is Polish for “please”, so the tone is courteous and plain, never fearful. The brand holds two things together: guarded and gracious, machine-exact and human-warm. It is not a padlock, a shield, a hooded figure or a cyan-on-black “cyber” look, because Prosze doesn’t lock your text away. It lends it a ticket and returns it.

## 2. Logo

| File | Use |
|---|---|
| `logo/prosze-mark.svg` | Mark alone, light backgrounds |
| `logo/prosze-mark-on-dark.svg` | Mark alone, dark backgrounds |
| `logo/prosze-mark-mono-ink.svg` / `-mono-white.svg` | One-colour uses (the bar becomes a cut-out) |
| `logo/prosze-logo.svg` / `-on-paper.svg` / `-on-dark.svg` | Horizontal lockups |
| `logo/prosze-app-icon.svg` | App icon, repo avatar, favicon |
| `logo/prosze.ico` | Windows icon, 16 to 256 px |
| `logo/prosze-favicon-32.png`, `-180.png` | Favicon and touch icon |
| `icons/prosze-icon-redact / restore / check / run` | Command icons (svg + png) |
| `social/prosze-social-banner.png` | Social preview, 1280×640 |

PNG exports are included. Text in the SVGs is converted to outlines, so no font is needed.

**Clear space:** one notch diameter (the width of the semicircle cut from the ticket’s edge) on every side.
**Minimum size:** mark 16 px, lockup 120 px wide.

**Don’t:** move the red bar off the left body; recolour the bar or use it twice in one layout; straighten, rotate further or mirror the ticket; add shadows, gradients or a lock/shield; set the wordmark in capitals.

## 3. Color

| Name | Hex | Role |
|---|---|---|
| Cloakroom Pine | `#12392F` | Primary brand color, ticket body, text on paper |
| Stamp Red | `#E8432A` | The one hot accent: the redaction bar, placeholder chips. Once per layout |
| Ticket Cream | `#F5EFE2` | Paper, ticket on dark |
| Ink | `#0F1A17` | Text and dark ground |
| Pine Mint | `#8FD0B3` | Primary lifted for dark backgrounds (taglines, labels) |
| Slate | `#56635D` | Secondary text |
| Perforation | `#D9D1BF` | Hairlines and dividers on paper |

Proportions: about 60% cream or pine, 30% the other of the two (or ink), 10% or less stamp red.

Contrast checks: Cream on Pine 11.1:1; Ink on Cream 15.5:1; Slate on Cream 5.5:1; Mint on Ink 10.0:1; Pine on Cream 11.1:1; Stamp Red against Cream 3.5:1 and against Pine 3.2:1 (graphics only, both above 3:1). Never set body text in Stamp Red; on dark grounds a lighter red (`#FF6A4D`, 4.5:1 on Pine) is allowed for accent text.

## 4. Typography

- **Fraunces 600 (soft, optical size 72):** wordmark, lowercase, tracking -2%. Headlines in Fraunces 500.
- **Schibsted Grotesk 400/500/700:** body text and interface.
- Placeholders, commands and tokens are set in the user’s own monospace (the brand board uses JetBrains Mono): the terminal is where Prosze lives.
- Fallback: system serif for display, system sans-serif for body. All fonts are free on Google Fonts.

## 5. Motion, pattern and icons

**Motion:** the round trip. A real value (`Jan Kowalski`) is stamped, tears off along the perforation and becomes its ticket (`[[PERSON_1]]`); on return the ticket slides back and the value reappears. Short, 200 to 300 ms, ease-out, no bouncing and no glow.

**Pattern:** the perforation, a row of short rounded dashes, is the divider and the border device. The notch (a semicircle bitten from an edge) can mark corners of cards and screenshots.

**Signature device:** the placeholder chip, `[[PERSON_1]]` in monospace on a Stamp Red pill. Use it in banners, docs and screenshots wherever the product’s behavior is shown.

**Icons:** outline style, a notched ticket with one glyph inside: redact (red bar), restore (text lines), check (tick), run (prompt). 11-unit stroke on a 96-unit grid, round joins, red used once.

**Imagery:** none of hands, locks or screens of code. Show the before and after of a sentence.

## 6. Voice

Courteous, exact, calm. Describe what happens to the text, not the technology.

- **Say what happens.** Yes: “Your email becomes `[[EMAIL_1]]` before the prompt leaves.” No: “Military-grade AI-powered PII protection.”
- **No fear.** Yes: “Nothing leaves until it has a ticket.” No: “Hackers are everywhere. Don’t get exposed.”
- **Be honest about limits.** Yes: “Names are found by heuristics; add anything important with `--term`.” No: “100% guaranteed protection.”

Alternate taglines: “Hand it over. Get it back.” (the mechanism) and “Here you go.” (the Polish *proszę*, for playful moments).

## 7. Usage

- **Repo avatar and favicon:** `prosze-app-icon.svg`.
- **Social preview:** `social/prosze-social-banner.png` (upload under repo Settings, Social preview).
- **README header:** `prosze-logo.svg` at about 360 px wide; on dark README themes use `prosze-logo-on-dark.svg`.
- **GitHub description line:** “A local privacy shield for the text you send to AI.”
- **Windows binary:** embed `prosze.ico`.
- **Terminal output:** keep placeholders in the form `[[TYPE_n]]` and, where color is available, render them in Stamp Red on cream or the lighter red on dark.
