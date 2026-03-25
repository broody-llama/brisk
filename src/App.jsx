import { useMemo, useState } from 'react'

const RISK_LIBRARY = {
  saas: [
    { id: 1, title: 'Unauthorized access to vendor tenant', description: 'Weak IAM controls can allow unauthorized access to Block data.', severity: 'HIGH', impact: 'Data exposure and incident response overhead.' },
    { id: 2, title: 'Inadequate encryption controls', description: 'Data may be insufficiently protected in transit or at rest.', severity: 'HIGH', impact: 'Confidentiality compromise and compliance issues.' },
    { id: 3, title: 'Logging and monitoring gaps', description: 'Insufficient audit logging can delay detection of malicious activity.', severity: 'MEDIUM', impact: 'Longer dwell time and delayed containment.' },
    { id: 4, title: 'Vendor outage affects operations', description: 'Service downtime can block business-critical workflows.', severity: 'MEDIUM', impact: 'Operational disruption and manual fallback burden.' },
  ],
  payments: [
    { id: 1, title: 'Fraud and transaction manipulation', description: 'Weak transaction controls increase fraud risk.', severity: 'CRITICAL', impact: 'Financial loss and customer trust impact.' },
    { id: 2, title: 'PCI scope and compliance drift', description: 'Control failures may violate PCI obligations.', severity: 'HIGH', impact: 'Regulatory findings and remediation costs.' },
    { id: 3, title: 'Settlement and reconciliation failures', description: 'Processing or reporting issues can break financial reconciliation.', severity: 'HIGH', impact: 'Revenue leakage and accounting risk.' },
    { id: 4, title: 'Third-party dependency outage', description: 'Upstream failures may interrupt payment flows.', severity: 'MEDIUM', impact: 'Payment delays and operational incident load.' },
  ],
  analytics: [
    { id: 1, title: 'Excessive data collection', description: 'Analytics integrations may ingest more data than needed.', severity: 'HIGH', impact: 'Privacy exposure and policy violations.' },
    { id: 2, title: 'Cross-border data transfer risk', description: 'Data residency or transfer requirements may not be met.', severity: 'HIGH', impact: 'Regulatory non-compliance and legal risk.' },
    { id: 3, title: 'Model or insight integrity risk', description: 'Poor data quality controls can produce misleading outputs.', severity: 'MEDIUM', impact: 'Bad decisions and operational inefficiency.' },
  ],
  infrastructure: [
    { id: 1, title: 'Privileged access abuse', description: 'Infrastructure providers often hold broad privileged access.', severity: 'CRITICAL', impact: 'Large blast radius compromise.' },
    { id: 2, title: 'Supply chain vulnerability', description: 'Compromised dependencies or images can propagate risk.', severity: 'HIGH', impact: 'Widespread service compromise.' },
    { id: 3, title: 'Resilience configuration gaps', description: 'Misconfigured backup/DR can increase outage duration.', severity: 'HIGH', impact: 'Extended downtime and service degradation.' },
  ],
}

const escapeXml = (value) =>
  value
    .trim()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')

const dueDateFor = (risks) => {
  const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  const top = risks.reduce((highest, risk) =>
    order.indexOf(risk.severity) > order.indexOf(highest) ? risk.severity : highest,
  'LOW')

  const days = { CRITICAL: 30, HIGH: 30, MEDIUM: 60, LOW: 90 }[top]
  const due = new Date()
  due.setDate(due.getDate() + days)
  return due.toISOString().slice(0, 10)
}

const buildTicket = (vendorName, vendorType) => {
  const safeName = escapeXml(vendorName)
  const risks = RISK_LIBRARY[vendorType]
  const created = new Date().toISOString().slice(0, 10)
  const dueDate = dueDateFor(risks)

  const risksBlock = risks
    .map((risk) => `- Risk ID: ${risk.id}\n- Risk Title: ${escapeXml(risk.title)}\n- Description: ${escapeXml(risk.description)}\n- Severity: ${risk.severity}\n- Potential Impact: ${escapeXml(risk.impact)}\n`)
    .join('\n')

  const controlsBlock = risks
    .map((risk, index) => `- Control ID: ${index + 1}\n- Related Risk ID(s): ${risk.id}\n- Control Description: Implement preventive and detective controls aligned to the risk, documented in vendor security requirements.\n- DRI Status: Postponed\n- Implementation Notes: Validate through contract clauses, security questionnaire evidence, and annual control review.\n`)
    .join('\n')

  return `<risk_management_ticket>
<vendor_service_description>
Vendor ${safeName} is evaluated as a ${vendorType} provider supporting Block business operations.
- Data access and integrations must be validated during onboarding.
- Business purpose should be documented by the requesting team.
</vendor_service_description>

<security_risks>
${risksBlock}</security_risks>

<controls>
${controlsBlock}</controls>

<assignment_and_tracking>
- Assigned To: Unassigned - To be assigned to Block team member
- Created Date: ${created}
- Due Date: ${dueDate}
- Status: Open - Pending Review
</assignment_and_tracking>

<comments_section>
Comments and Discussion:
---
[No comments yet. Team members can add comments here to discuss risks, controls, and implementation status.]
</comments_section>
</risk_management_ticket>`
}

function App() {
  const [vendorName, setVendorName] = useState('')
  const [vendorType, setVendorType] = useState('saas')
  const [touched, setTouched] = useState(false)

  const isValidName = vendorName.trim().length > 0

  const output = useMemo(() => {
    if (!isValidName) return ''
    return buildTicket(vendorName, vendorType)
  }, [vendorName, vendorType, isValidName])

  return (
    <main className="page">
      <section className="card">
        <h1>Brisk Risk Ticket Generator</h1>
        <p>Generate risk-management XML tickets for common vendor types.</p>

        <label>
          Vendor name
          <input
            value={vendorName}
            onChange={(e) => setVendorName(e.target.value)}
            onBlur={() => setTouched(true)}
            placeholder="Acme Vendor"
          />
        </label>

        {!isValidName && touched && <p className="error">Vendor name is required.</p>}

        <label>
          Vendor type
          <select value={vendorType} onChange={(e) => setVendorType(e.target.value)}>
            {Object.keys(RISK_LIBRARY).map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>

        <label>
          Generated XML
          <textarea value={output} readOnly rows={22} placeholder="Generated XML will appear here." />
        </label>

        <button
          type="button"
          disabled={!output}
          onClick={() => navigator.clipboard.writeText(output)}
        >
          Copy XML
        </button>
      </section>
    </main>
  )
}

export default App
