/**
 * SVG Badge Generator for ArcShield
 * Generates shields.io style badges for security scan results
 */

export interface BadgeOptions {
  label: string;
  message: string;
  color: string;
  labelColor?: string;
}

/**
 * Generate an SVG badge (shields.io style)
 */
export function generateBadgeSVG(options: BadgeOptions): string {
  const { label, message, color, labelColor = '555' } = options;

  // Calculate widths (approximate character width of 6.5px for Verdana 11px)
  const labelWidth = label.length * 6.5 + 10;
  const messageWidth = message.length * 6.5 + 10;
  const totalWidth = labelWidth + messageWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${message}">
  <title>${label}: ${message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#${labelColor}"/>
    <rect x="${labelWidth}" width="${messageWidth}" height="20" fill="#${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${labelWidth * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">${escapeXml(label)}</text>
    <text x="${labelWidth * 5}" y="140" transform="scale(.1)" fill="#fff">${escapeXml(label)}</text>
    <text aria-hidden="true" x="${labelWidth * 10 + messageWidth * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">${escapeXml(message)}</text>
    <text x="${labelWidth * 10 + messageWidth * 5}" y="140" transform="scale(.1)" fill="#fff">${escapeXml(message)}</text>
  </g>
</svg>`;
}

/**
 * Escape XML special characters
 */
function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Get color based on security score
 */
export function getScoreColor(score: number): string {
  if (score >= 90) return '4c1';      // Bright green
  if (score >= 80) return '97ca00';   // Green
  if (score >= 70) return 'a4a61d';   // Yellow-green
  if (score >= 60) return 'dfb317';   // Yellow
  if (score >= 50) return 'fe7d37';   // Orange
  return 'e05d44';                     // Red
}

/**
 * Generate ArcShield Verified badge
 */
export function generateVerifiedBadge(eligible: boolean): string {
  if (eligible) {
    return generateBadgeSVG({
      label: 'ArcShield',
      message: 'Verified',
      color: '4c1', // Green
    });
  } else {
    return generateBadgeSVG({
      label: 'ArcShield',
      message: 'Not Verified',
      color: 'e05d44', // Red
    });
  }
}

/**
 * Generate ArcShield Score badge
 */
export function generateScoreBadge(score: number): string {
  return generateBadgeSVG({
    label: 'ArcShield',
    message: `${score}/100`,
    color: getScoreColor(score),
  });
}

/**
 * Generate a combined status badge
 */
export function generateStatusBadge(score: number, eligible: boolean): string {
  if (eligible) {
    return generateBadgeSVG({
      label: 'ArcShield',
      message: `Verified ${score}/100`,
      color: '4c1',
    });
  } else {
    return generateBadgeSVG({
      label: 'ArcShield',
      message: `${score}/100`,
      color: getScoreColor(score),
    });
  }
}
