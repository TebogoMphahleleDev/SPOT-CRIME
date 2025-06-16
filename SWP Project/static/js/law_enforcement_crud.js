document.addEventListener('DOMContentLoaded', function() {
  const socket = io();

  socket.on('new_incident', function(data) {
    showToast('New Incident Reported: ' + data.incident_type + ' at ' + data.location, 'info');
  });

  const createOfficerBtn = document.getElementById('createOfficerBtn');
  const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
  let currentDeleteOfficerId = null;

  // Create Officer Modal Elements
  const officerModalElement = document.createElement('div');
  officerModalElement.innerHTML = `
  <div class="modal fade" id="officerModal" tabindex="-1" aria-labelledby="officerModalLabel" aria-hidden="true">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="officerModalLabel">Add Law Enforcement Officer</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <form id="officerForm">
            <input type="hidden" id="officer_id" name="officer_id">
            <div class="mb-3">
              <label for="officer_email" class="form-label">Email</label>
              <input type="email" class="form-control" id="officer_email" name="email" required>
            </div>
            <div class="mb-3">
              <label for="officer_password" class="form-label">Password</label>
              <input type="password" class="form-control" id="officer_password" name="password" required>
            </div>
            <div class="mb-3">
              <label for="officer_station" class="form-label">Station</label>
              <input type="text" class="form-control" id="officer_station" name="station" required>
            </div>
            <div class="mb-3">
              <label for="officer_badge_number" class="form-label">Badge Number</label>
              <input type="text" class="form-control" id="officer_badge_number" name="badge_number" required>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
          <button type="button" class="btn btn-primary" id="saveOfficerBtn">Save</button>
        </div>
      </div>
    </div>
  </div>
  `;
  document.body.appendChild(officerModalElement);
  const officerModal = new bootstrap.Modal(document.getElementById('officerModal'));

  // Show modal for creating new officer
  createOfficerBtn.addEventListener('click', () => {
    resetOfficerForm();
    document.getElementById('officerModalLabel').textContent = 'Add Law Enforcement Officer';
    document.getElementById('officer_password').required = true;
    document.getElementById('saveOfficerBtn').onclick = createOfficer;
    officerModal.show();
  });

  // Reset officer form
  function resetOfficerForm() {
    const form = document.getElementById('officerForm');
    form.reset();
    document.getElementById('officer_id').value = '';
  }

  // Create officer
  function createOfficer() {
    const formData = getOfficerFormData();
    if (!formData) return;

    fetch('/admin/create_officer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        officerModal.hide();
        showToast('Officer created successfully', 'success');
        setTimeout(() => location.reload(), 1000);
      } else {
        showToast('Error creating officer: ' + data.message, 'danger');
      }
    })
    .catch(err => {
      console.error(err);
      showToast('Error creating officer', 'danger');
    });
  }

  // Get form data and validate
  function getOfficerFormData() {
    const email = document.getElementById('officer_email').value.trim();
    const password = document.getElementById('officer_password').value;
    const station = document.getElementById('officer_station').value.trim();
    const badge_number = document.getElementById('officer_badge_number').value.trim();

    if (!email || !station || !badge_number) {
      showToast('Please fill in all required fields', 'warning');
      return null;
    }

    const officerId = document.getElementById('officer_id').value;
    const data = { email, station, badge_number };
    if (!officerId) {
      if (!password) {
        showToast('Password is required for new officer', 'warning');
        return null;
      }
      data.password = password;
    } else {
      data.id = officerId;
      if (password) {
        data.password = password;
      }
    }
    return data;
  }

  // Edit officer buttons
  document.querySelectorAll('.edit-officer-btn').forEach(button => {
    button.addEventListener('click', () => {
      const row = button.closest('tr');
      const officerId = row.getAttribute('data-officer-id');

      fetch(`/admin/get_officer/${officerId}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          populateOfficerForm(data.officer);
          document.getElementById('officerModalLabel').textContent = 'Edit Law Enforcement Officer';
          document.getElementById('officer_password').required = false;
          document.getElementById('saveOfficerBtn').onclick = updateOfficer;
          officerModal.show();
        } else {
          showToast('Error fetching officer: ' + data.message, 'danger');
        }
      })
      .catch(err => {
        console.error(err);
        showToast('Error fetching officer details', 'danger');
      });
    });
  });

  // Populate officer form for editing
  function populateOfficerForm(officer) {
    document.getElementById('officer_id').value = officer.id;
    document.getElementById('officer_email').value = officer.email;
    document.getElementById('officer_station').value = officer.station;
    document.getElementById('officer_badge_number').value = officer.badge_number;
    document.getElementById('officer_password').value = '';
  }

  // Update officer
  function updateOfficer() {
    const formData = getOfficerFormData();
    if (!formData) return;

    fetch(`/admin/update_officer/${formData.id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        officerModal.hide();
        showToast('Officer updated successfully', 'success');
        setTimeout(() => location.reload(), 1000);
      } else {
        showToast('Error updating officer: ' + data.message, 'danger');
      }
    })
    .catch(err => {
      console.error(err);
      showToast('Error updating officer', 'danger');
    });
  }

  // Delete officer buttons
  document.querySelectorAll('.delete-officer-btn').forEach(button => {
    button.addEventListener('click', () => {
      const row = button.closest('tr');
      currentDeleteOfficerId = row.getAttribute('data-officer-id');
      document.getElementById('deleteModalLabel').textContent = 'Confirm Delete Officer';
      document.getElementById('confirmDeleteBtn').onclick = deleteOfficer;
      deleteModal.show();
    });
  });

  // Delete officer
  function deleteOfficer() {
    if (!currentDeleteOfficerId) return;

    fetch(`/admin/delete_officer/${currentDeleteOfficerId}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        deleteModal.hide();
        showToast('Officer deleted successfully', 'success');
        setTimeout(() => location.reload(), 1000);
      } else {
        showToast('Error deleting officer: ' + data.message, 'danger');
      }
    })
    .catch(err => {
      console.error(err);
      showToast('Error deleting officer', 'danger');
    });
  }

  // Toast notification function (reuse from admindashboard)
  function showToast(message, type = 'primary') {
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = 'toast align-items-center text-white bg-' + type + ' border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    toast.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">
          ${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    `;

    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', function() {
      toast.remove();
    });
  }

  function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    document.body.appendChild(container);
    return container;
  }
});
