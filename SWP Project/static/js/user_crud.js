document.addEventListener('DOMContentLoaded', function() {
  const userModal = new bootstrap.Modal(document.getElementById('userModal'));
  const userForm = document.getElementById('userForm');
  const saveUserBtn = document.getElementById('saveUserBtn');
  const usersTableBody = document.querySelector('#users-table tbody');
  let editingUserId = null;

  // Edit user buttons
  usersTableBody.querySelectorAll('.edit-user-btn').forEach(button => {
    button.addEventListener('click', () => {
      const tr = button.closest('tr');
      editingUserId = tr.getAttribute('data-user-id');

      fetch(`/admin/users/${editingUserId}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      })
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          const user = result.user;
          document.getElementById('edit_user_id').value = user.id;
          document.getElementById('edit_name').value = user.name || '';
          document.getElementById('edit_email').value = user.email || '';
          document.getElementById('edit_phone').value = user.phone || '';
          document.getElementById('edit_address').value = user.address || '';
          document.getElementById('userModalLabel').textContent = 'Edit User';
          saveUserBtn.textContent = 'Update';
          userModal.show();
        } else {
          alert(result.message || 'Error fetching user data');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Error fetching user data');
      });
    });
  });

  // Save user (update)
  saveUserBtn.addEventListener('click', () => {
    if (!editingUserId) {
      alert('No user selected for update');
      return;
    }

    const data = {
      name: document.getElementById('edit_name').value.trim(),
      email: document.getElementById('edit_email').value.trim(),
      phone: document.getElementById('edit_phone').value.trim(),
      address: document.getElementById('edit_address').value.trim()
    };

    fetch(`/admin/users/${editingUserId}/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
      if (result.success) {
        userModal.hide();
        alert(result.message);
        location.reload();
      } else {
        alert(result.message || 'Error updating user');
      }
    })
    .catch(error => {
      console.error('Error:', error);
      alert('Error updating user');
    });
  });

  // Delete user buttons
  usersTableBody.querySelectorAll('.delete-user-btn').forEach(button => {
    button.addEventListener('click', () => {
      if (!confirm('Are you sure you want to delete this user?')) {
        return;
      }
      const tr = button.closest('tr');
      const userId = tr.getAttribute('data-user-id');

      fetch(`/admin/users/${userId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }
      })
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          alert(result.message);
          location.reload();
        } else {
          alert(result.message || 'Error deleting user');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Error deleting user');
      });
    });
  });

  // Toggle user status buttons
  usersTableBody.querySelectorAll('.toggle-user-status-btn').forEach(button => {
    button.addEventListener('click', () => {
      const tr = button.closest('tr');
      const userId = tr.getAttribute('data-user-id');

      fetch(`/admin/users/${userId}/toggle-status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          alert(result.message);
          location.reload();
        } else {
          alert(result.message || 'Error toggling user status');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Error toggling user status');
      });
    });
  });
});
