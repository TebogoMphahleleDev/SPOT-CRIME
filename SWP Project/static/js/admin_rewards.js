document.addEventListener('DOMContentLoaded', function() {
  // Approve reward button click handler
  document.querySelectorAll('.approve-reward-btn').forEach(button => {
    button.addEventListener('click', function() {
      const voucherId = this.getAttribute('data-voucher-id');
      if (!voucherId) return;

      fetch(`/admin/approve_voucher/${voucherId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert('Voucher approved successfully');
          // Reload page or update UI
          location.reload();
        } else {
          alert(data.error || 'Failed to approve voucher');
        }
      })
      .catch(error => {
        console.error('Error approving voucher:', error);
        alert('Error approving voucher');
      });
    });
  });

  // Reject reward button click handler
  document.querySelectorAll('.reject-reward-btn').forEach(button => {
    button.addEventListener('click', function() {
      const voucherId = this.getAttribute('data-voucher-id');
      if (!voucherId) return;

      if (!confirm('Are you sure you want to reject this voucher? This will refund the points.')) {
        return;
      }

      fetch(`/admin/reject_voucher/${voucherId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert('Voucher rejected and points refunded');
          // Reload page or update UI
          location.reload();
        } else {
          alert(data.error || 'Failed to reject voucher');
        }
      })
      .catch(error => {
        console.error('Error rejecting voucher:', error);
        alert('Error rejecting voucher');
      });
    });
  });
});
