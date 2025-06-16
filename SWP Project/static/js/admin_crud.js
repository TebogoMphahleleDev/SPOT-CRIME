document.addEventListener('DOMContentLoaded', function() {
  const adminModal = new bootstrap.Modal(document.getElementById('adminModal'));
  const adminForm = document.getElementById('adminForm');
  const saveAdminBtn = document.getElementById('saveAdminBtn');
  const createAdminBtn = document.getElementById('createAdminBtn');
  const adminsTableBody = document.querySelector('#admins-table tbody');
  let editingAdminId = null;

  // Open modal for creating new admin
  createAdminBtn.addEventListener('click', () => {
    editingAdminId = null;
    adminForm.reset();
    document.getElementById('adminModalLabel').textContent = 'Add Admin';
    saveAdminBtn.textContent = 'Save';
    adminModal.show();
  });

  // Save admin (create or update)
  saveAdminBtn.addEventListener('click', () => {
    const email = document.getElementById('admin_email').value.trim();
    const password = document.getElementById('admin_password').value;

    if (!email) {
      alert('Email is required');
      return;
    }
    if (!password && !editingAdminId) {
      alert('Password is required for new admin');
      return;
    }

    const url = editingAdminId ? `/admin/update_admin/${editingAdminId}` : '/admin/create_admin';
    const method = 'POST';
    const data = editingAdminId ? { email } : { email, password };

    fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
      if (result.success) {
        adminModal.hide();
        alert(result.message);
        // Reload page or update table row
        location.reload();
      } else {
        alert(result.message || 'Error saving admin');
      }
    })
    .catch(error => {
      console.error('Error:', error);
      alert('Error saving admin');
    });
  });

  // Edit admin buttons
  adminsTableBody.querySelectorAll('.edit-admin-btn').forEach(button => {
    button.addEventListener('click', () => {
      const tr = button.closest('tr');
      const adminId = tr.getAttribute('data-admin-id');

      fetch(`/admin/get_admin/${adminId}`)
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          editingAdminId = adminId;
          document.getElementById('admin_email').value = result.admin.email;
          document.getElementById('admin_password').value = '';
          document.getElementById('adminModalLabel').textContent = 'Edit Admin';
          saveAdminBtn.textContent = 'Update';
          adminModal.show();
        } else {
          alert(result.message || 'Error fetching admin data');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Error fetching admin data');
      });
    });
  });

  // Delete admin buttons
  adminsTableBody.querySelectorAll('.delete-admin-btn').forEach(button => {
    button.addEventListener('click', () => {
      if (!confirm('Are you sure you want to delete this admin?')) {
        return;
      }
      const tr = button.closest('tr');
      const adminId = tr.getAttribute('data-admin-id');

      fetch(`/admin/delete_admin/${adminId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }
      })
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          alert(result.message);
          // Remove row or reload page
          location.reload();
        } else {
          alert(result.message || 'Error deleting admin');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Error deleting admin');
      });
    });
  });
});
