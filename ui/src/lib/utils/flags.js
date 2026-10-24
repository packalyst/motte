// Country flags, served by the panel itself (flag-icons, bundled at build time) rather than
// fetched from a flag website: nothing outside the panel learns which countries are being looked
// at, and the pages stay within the Content Security Policy (images from the panel only).
// `?no-inline` keeps each flag its own file, fetched only when shown, instead of all of them
// landing in the app's code.
const FLAGS = import.meta.glob('/node_modules/flag-icons/flags/4x3/*.svg', { query: '?no-inline', import: 'default', eager: true })

/** The flag image URL for a two-letter country code, or null when there is none. */
export function flagUrl(code) {
  const c = String(code || '').toLowerCase()
  return /^[a-z]{2}$/.test(c) ? FLAGS[`/node_modules/flag-icons/flags/4x3/${c}.svg`] || null : null
}
