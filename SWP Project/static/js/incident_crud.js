
document.addEventListener('DOMContentLoaded', () => {
  console.log('incident_crud.js loaded');

  const incidentModalEl = document.getElementById('incidentModal');
  const incidentModal = new bootstrap.Modal(incidentModalEl);
  const viewIncidentModalEl = document.getElementById('viewIncidentModal');
  const viewIncidentModal = new bootstrap.Modal(viewIncidentModalEl);

  const incidentForm = document.getElementById('incidentForm');
  const saveIncidentBtn = document.getElementById('saveIncidentBtn');
  const incidentsTableBody = document.querySelector('#incidents-table tbody');

  let editingIncidentId = null;

  // Reset and open create incident modal
  function openCreateModal() {
    editingIncidentId = null;
    incidentForm.reset();
    document.getElementById('notes').value = '';
    document.getElementById('incidentModalLabel').textContent = 'Create New Incident';
    saveIncidentBtn.textContent = 'Create';

    // Use Geolocation API to get current location
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          document.getElementById('latitude').value = position.coords.latitude.toFixed(6);
          document.getElementById('longitude').value = position.coords.longitude.toFixed(6);
          // Optionally, you can implement reverse geocoding here to get address from lat/lng
          // For now, clear address field
          document.getElementById('address').value = '';
        },
        (error) => {
          console.warn('Geolocation error:', error.message);
          // Clear location fields if error
          document.getElementById('latitude').value = '';
          document.getElementById('longitude').value = '';
          document.getElementById('address').value = '';
        }
      );
    } else {
      console.warn('Geolocation is not supported by this browser.');
      document.getElementById('latitude').value = '';
      document.getElementById('longitude').value = '';
      document.getElementById('address').value = '';
    }

    incidentModal.show();
  }

  // Open edit incident modal with data
  function openEditModal(incident) {
    editingIncidentId = incident.id;
    document.getElementById('incident_id').value = incident.id;
    document.getElementById('crime_type').value = incident.crime_type || '';
    document.getElementById('description').value = incident.description || '';
    document.getElementById('latitude').value = incident.latitude || '';
    document.getElementById('longitude').value = incident.longitude || '';
    document.getElementById('address').value = incident.address || '';
    document.getElementById('user_id').value = incident.user_id || '';
    document.getElementById('status').value = incident.status || 'reported';
    document.getElementById('notes').value = incident.notes || '';
    document.getElementById('incidentModalLabel').textContent = 'Edit Incident';
    saveIncidentBtn.textContent = 'Update';
    incidentModal.show();
  }

  // Open view incident modal with data
  async function openViewModal(incident) {
    document.getElementById('view_incident_id').textContent = incident.id;
    document.getElementById('view_crime_type').textContent = incident.crime_type || '';
    document.getElementById('view_description').textContent = incident.description || '';
    document.getElementById('view_latitude').textContent = incident.latitude || '';
    document.getElementById('view_longitude').textContent = incident.longitude || '';
    document.getElementById('view_address').textContent = incident.address || '';
    document.getElementById('view_status').textContent = incident.status || '';
    document.getElementById('view_created_at').textContent = incident.created_at || '';
    document.getElementById('view_notes').textContent = incident.notes || '';
    
    if (incident.assigned_officer) {
      document.getElementById('view_assigned_officer').textContent = incident.assigned_officer.email || 'N/A';
    } else {
      document.getElementById('view_assigned_officer').textContent = 'N/A';
    }
    
    if (incident.user) {
      document.getElementById('view_user_name').textContent = incident.user.name || 'null';
      document.getElementById('view_user_email').textContent = incident.user.email || 'null';
      document.getElementById('view_user_phone').textContent = incident.user.phone || 'null';
      document.getElementById('view_user_address').textContent = incident.user.address || 'null';
    } else {
      document.getElementById('view_user_name').textContent = 'null';
      document.getElementById('view_user_email').textContent = 'null';
      document.getElementById('view_user_phone').textContent = 'null';
      document.getElementById('view_user_address').textContent = 'null';
    }

    // Fetch evidence files from API
    const evidenceContainer = document.getElementById('view_evidence');
    evidenceContainer.innerHTML = '<p>Loading evidence...</p>';
    try {
      const response = await fetch(`/api/incident_evidence/${incident.id}`);
      if (!response.ok) {
        console.error(`Failed to fetch evidence: HTTP ${response.status}`);
        evidenceContainer.innerHTML = '<p>Error loading evidence.</p>';
        return;
      }
      const data = await response.json();
      if (data.success && data.evidence.length > 0) {
        evidenceContainer.innerHTML = '';
        data.evidence.forEach(ev => {
          let element;
          const fileUrl = `/uploads/${ev.file_path}`;
          if (ev.file_type === 'image') {
            element = document.createElement('img');
            element.src = fileUrl;
            element.alt = 'Evidence Image';
            element.style.maxWidth = '150px';
            element.style.maxHeight = '150px';
            element.style.borderRadius = '8px';
            element.style.objectFit = 'cover';
            element.onerror = () => {
              console.error(`Failed to load image: ${fileUrl}`);
              element.style.display = 'none';
            };
          } else if (ev.file_type === 'video') {
            element = document.createElement('video');
            element.src = fileUrl;
            element.controls = true;
            element.style.maxWidth = '200px';
            element.style.maxHeight = '150px';
            element.style.borderRadius = '8px';
            element.onerror = () => {
              console.error(`Failed to load video: ${fileUrl}`);
              element.style.display = 'none';
            };
          } else if (ev.file_type === 'audio') {
            element = document.createElement('audio');
            element.src = fileUrl;
            element.controls = true;
            element.style.width = '100%';
            element.onerror = () => {
              console.error(`Failed to load audio: ${fileUrl}`);
              element.style.display = 'none';
            };
          } else {
            element = document.createElement('a');
            element.href = fileUrl;
            element.textContent = 'Download file';
            element.target = '_blank';
          }
          evidenceContainer.appendChild(element);
        });
      } else {
        evidenceContainer.innerHTML = '<p>No evidence available.</p>';
      }
    } catch (error) {
      console.error('Error loading evidence:', error);
      evidenceContainer.innerHTML = '<p>Error loading evidence.</p>';
    }

    viewIncidentModal.show();
  }

  // Fetch incident data by ID
  async function fetchIncident(id) {
    try {
      const response = await fetch(`/admin/get_incident/${id}`);
      const data = await response.json();
      if (data.success) {
        return data.incident;
      } else {
        alert(data.message || 'Failed to fetch incident data');
        return null;
      }
    } catch (error) {
      console.error('Fetch incident error:', error);
      alert('Error fetching incident data');
      return null;
    }
  }

  // Handle create incident button click
  document.querySelectorAll('#createIncidentBtn, #createIncidentBtn2').forEach(btn => {
    btn.addEventListener('click', openCreateModal);
  });

  // Event delegation for incident action buttons
  incidentsTableBody.addEventListener('click', async (event) => {
    const button = event.target.closest('button');
    if (!button) return;

    const tr = button.closest('tr');
    if (!tr) return;

    const incidentId = tr.getAttribute('data-incident-id');
    if (!incidentId) return;

    if (button.classList.contains('view-incident-btn')) {
      const incident = await fetchIncident(incidentId);
      if (incident) openViewModal(incident);
    } else if (button.classList.contains('edit-incident-btn')) {
      const incident = await fetchIncident(incidentId);
      if (incident) openEditModal(incident);
    } else if (button.classList.contains('delete-incident-btn')) {
      if (!confirm('Are you sure you want to delete this incident?')) return;
      try {
        const response = await fetch(`/admin/delete_incident/${incidentId}`, { method: 'DELETE' });
        const data = await response.json();
        if (data.success) {
          alert(data.message);
          location.reload();
        } else {
          alert(data.message || 'Failed to delete incident');
        }
      } catch (error) {
        console.error('Delete incident error:', error);
        alert('Error deleting incident');
      }
    } else if (button.classList.contains('verify-incident-btn')) {
      try {
        const response = await fetch(`/admin/verify_incident/${incidentId}`, { method: 'POST' });
        const data = await response.json();
        if (data.success) {
          alert(data.message);
          location.reload();
        } else {
          alert(data.message || 'Failed to verify incident');
        }
      } catch (error) {
        console.error('Verify incident error:', error);
        alert('Error verifying incident');
      }
    }
  });

  // Handle save incident button click (create or update)
  saveIncidentBtn.addEventListener('click', async () => {
    const data = {
      crime_type: document.getElementById('crime_type').value.trim(),
      description: document.getElementById('description').value.trim(),
      latitude: parseFloat(document.getElementById('latitude').value),
      longitude: parseFloat(document.getElementById('longitude').value),
      address: document.getElementById('address').value.trim(),
      user_id: document.getElementById('user_id').value ? parseInt(document.getElementById('user_id').value) : null,
      status: document.getElementById('status').value,
      notes: document.getElementById('notes').value.trim()
    };

    let url = '/admin/create_incident';
    let method = 'POST';

    if (editingIncidentId) {
      url = `/admin/update_incident/${editingIncidentId}`;
      method = 'POST';
    }

    try {
      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      const result = await response.json();
      if (result.success) {
        incidentModal.hide();
        alert(result.message);
        location.reload();
      } else {
        alert(result.message || 'Failed to save incident');
      }
    } catch (error) {
      console.error('Save incident error:', error);
      alert('Error saving incident');
    }
  });

  // Generate Report Modal Elements
  const generateReportBtn = document.getElementById('generateReportBtn');
  const generateReportModal = new bootstrap.Modal(document.getElementById('generateReportModal'));
  const reportForm = document.getElementById('reportForm');
  const reportResults = document.getElementById('reportResults');

  // Open the Generate Report modal on button click
  generateReportBtn.addEventListener('click', () => {
    // Clear previous results and form inputs
    reportResults.innerHTML = '';
    reportForm.reset();
    generateReportModal.show();
  });

  // Handle form submission to generate report
  reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Disable submit button to prevent multiple requests
    const submitBtn = document.getElementById('generateReportSubmitBtn');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Generating...';

    // Get filter values
    const caseType = document.getElementById('filterCaseType').value.trim();
    const userIdRaw = document.getElementById('filterUserId').value.trim();

    // Prepare payload
    const payload = {};
    if (caseType) payload.case_type = caseType;
    if (userIdRaw) {
      const userId = parseInt(userIdRaw, 10);
      if (!isNaN(userId)) {
        payload.user_id = userId;
      } else {
        // If userIdRaw is not a valid number, do not include user_id in payload
        delete payload.user_id;
      }
    }

    try {
      const response = await fetch('/admin/generate_report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error('Failed to generate report');
      }

      const data = await response.json();

      if (data.error) {
        reportResults.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
      } else if (data.report && data.report.length > 0) {
        // Build report table
        let html = '<table class="table table-striped table-bordered">';
        html += '<thead><tr><th>ID</th><th>Crime Type</th><th>Status</th><th>Assigned Officer</th><th>Notes</th><th>Reporter</th></tr></thead><tbody>';
        data.report.forEach(item => {
          html += `<tr>
            <td>#${item.id}</td>
            <td>${item.crime_type}</td>
            <td>${item.status}</td>
            <td>${item.assigned_officer_email || 'N/A'}</td>
            <td>${item.notes || ''}</td>
            <td>${item.reporter ? (item.reporter.name || 'N/A') : 'N/A'} (${item.reporter ? (item.reporter.email || 'N/A') : 'N/A'})</td>
          </tr>`;
        });
        html += '</tbody></table>';
        reportResults.innerHTML = html;
      } else {
        reportResults.innerHTML = '<div class="alert alert-info">No incidents found for the selected filters.</div>';
      }
    } catch (error) {
      reportResults.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Generate Report';
    }
  });
});
