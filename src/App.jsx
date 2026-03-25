import { useMemo, useState } from 'react'

const VENDOR_TYPES = ['saas', 'payments', 'analytics', 'infrastructure', 'other']

const STATUS_OPTIONS = [
  'In Progress',
  'In Place',
  'Deferred',
  'Unavailable',
  'Waived',
  'Not Applicable',
]

function App() {
  const [vendorName, setVendorName] = useState('')
  const [vendorType, setVendorType] = useState('saas')
  const [evidenceText, setEvidenceText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [assessment, setAssessment] = useState(null)

  const canGenerate = useMemo(() => vendorName.trim() && evidenceText.trim(), [vendorName, evidenceText])

  const onGenerate = async () => {
    setLoading(true)
    setError('')
    try {
      const response = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vendor_name: vendorName, vendor_type: vendorType, evidence_text: evidenceText }),
      })
      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`)
      }
      const payload = await response.json()
      setAssessment(payload)
    } catch (err) {
      setError(err.message || 'Unable to generate assessment')
    } finally {
      setLoading(false)
    }
  }

  const updateControlStatus = (controlId, value) => {
    setAssessment((prev) => ({
      ...prev,
      controls: prev.controls.map((control) => (control.control_id === controlId ? { ...control, status: value } : control)),
    }))
  }

  return (
    <main className="page">
      <section className="card">
        <h1>Brisk — Vendor Risk Tracker</h1>
        <p>AI-assisted draft generation from vendor evidence. Review before approving.</p>

        <div className="grid">
          <label>
            Vendor name
            <input value={vendorName} onChange={(e) => setVendorName(e.target.value)} placeholder="Claude CoWork" />
          </label>

          <label>
            Vendor type
            <select value={vendorType} onChange={(e) => setVendorType(e.target.value)}>
              {VENDOR_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </label>
        </div>

        <label>
          Evidence / notes
          <textarea
            rows={8}
            value={evidenceText}
            onChange={(e) => setEvidenceText(e.target.value)}
            placeholder="Paste assessment notes or table rows here..."
          />
        </label>

        <button disabled={!canGenerate || loading} onClick={onGenerate} type="button">
          {loading ? 'Generating…' : 'Generate risk ticket'}
        </button>

        {error && <p className="error">{error}</p>}

        {assessment && (
          <>
            <section>
              <h2>Vendor service description</h2>
              <p>{assessment.vendor_service_description}</p>
            </section>

            <section>
              <h2>Risks</h2>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Potential Impact</th>
                  </tr>
                </thead>
                <tbody>
                  {assessment.risks.map((risk) => (
                    <tr key={risk.risk_id}>
                      <td>{risk.risk_id}</td>
                      <td>{risk.title}</td>
                      <td>{risk.severity}</td>
                      <td>{risk.potential_impact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>

            <section>
              <h2>Controls</h2>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Deploy</th>
                    <th>Related Risk(s)</th>
                  </tr>
                </thead>
                <tbody>
                  {assessment.controls.map((control) => (
                    <tr key={control.control_id}>
                      <td>{control.control_id}</td>
                      <td>{control.control_name}</td>
                      <td>
                        <select
                          value={control.status}
                          onChange={(e) => updateControlStatus(control.control_id, e.target.value)}
                        >
                          {STATUS_OPTIONS.map((status) => (
                            <option key={status} value={status}>
                              {status}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>{control.deployment_guidance}</td>
                      <td>{control.related_risk_ids.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          </>
        )}
      </section>
    </main>
  )
}

export default App
