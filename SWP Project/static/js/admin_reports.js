document.addEventListener('DOMContentLoaded', function() {
    const generateReportBtn = document.getElementById('generateReportSubmitBtn');
    const reportForm = document.getElementById('reportForm');
    const reportResults = document.getElementById('reportResults');
    
    if (generateReportBtn && reportForm) {
        generateReportBtn.addEventListener('click', function(e) {
            e.preventDefault();
            generateReport();
        });
    }

    function generateReport() {
        const formData = new FormData(reportForm);
        const data = {};
        
        // Convert FormData to JSON object
        formData.forEach((value, key) => {
            if (value) data[key] = value; // Only include fields with values
        });

        // Show loading state
        reportResults.innerHTML = `
            <div class="spinner-container">
                <div class="spinner"></div>
            </div>
            <p class="text-center mt-2">Generating report...</p>
        `;

        // Call the API
        fetch('/admin/generate_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': '{{ csrf_token() }}' // This needs to be set properly
            },
            body: JSON.stringify(data)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                displayReportResults(data.report_data);
            } else {
                reportResults.innerHTML = `
                    <div class="alert alert-danger">
                        ${data.message || 'Error generating report'}
                    </div>
                `;
            }
        })
        .catch(error => {
            reportResults.innerHTML = `
                <div class="alert alert-danger">
                    Error: ${error.message}
                </div>
            `;
            console.error('Error:', error);
        });
    }

    function displayReportResults(reportData) {
        window.reportData = reportData; // Store report data globally for export functions

        let html = `
            <div class="report-section mb-4">
                <h5><i class="fas fa-chart-pie me-2"></i>Summary Statistics</h5>
                <div class="table-responsive">
                    <table class="table table-bordered">
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Total Incidents</td>
                                <td>${reportData.summary.total_incidents}</td>
                            </tr>
                            <tr>
                                <td>Resolution Rate</td>
                                <td>${reportData.statistics.resolution_rate}%</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        // Add incidents by status
        if (reportData.summary.by_status) {
            html += `
                <div class="report-section mb-4">
                    <h5><i class="fas fa-list me-2"></i>Incidents by Status</h5>
                    <div class="table-responsive">
                        <table class="table table-bordered">
                            <thead>
                                <tr>
                                    <th>Status</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            for (const [status, count] of Object.entries(reportData.summary.by_status)) {
                html += `
                    <tr>
                        <td>${status}</td>
                        <td>${count}</td>
                    </tr>
                `;
            }
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // Add incidents by crime type
        if (reportData.summary.by_crime_type) {
            html += `
                <div class="report-section mb-4">
                    <h5><i class="fas fa-list me-2"></i>Incidents by Crime Type</h5>
                    <div class="table-responsive">
                        <table class="table table-bordered">
                            <thead>
                                <tr>
                                    <th>Crime Type</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            for (const [crimeType, count] of Object.entries(reportData.summary.by_crime_type)) {
                html += `
                    <tr>
                        <td>${crimeType}</td>
                        <td>${count}</td>
                    </tr>
                `;
            }
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // Add incidents by officer
        if (reportData.summary.by_officer) {
            html += `
                <div class="report-section mb-4">
                    <h5><i class="fas fa-user-shield me-2"></i>Incidents by Officer</h5>
                    <div class="table-responsive">
                        <table class="table table-bordered">
                            <thead>
                                <tr>
                                    <th>Officer</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            for (const [officer, count] of Object.entries(reportData.summary.by_officer)) {
                html += `
                    <tr>
                        <td>${officer}</td>
                        <td>${count}</td>
                    </tr>
                `;
            }
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // Add detailed incidents list
        if (reportData.incidents && reportData.incidents.length > 0) {
            html += `
                <div class="report-section mb-4">
                    <h5><i class="fas fa-table me-2"></i>Detailed Incidents (${reportData.incidents.length})</h5>
                    <div class="table-responsive">
                        <table class="table table-bordered" id="detailedIncidentsTable">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Crime Type</th>
                                    <th>Location</th>
                                    <th>Status</th>
                                    <th>Date</th>
                                    <th>User</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            reportData.incidents.forEach(incident => {
                html += `
                    <tr>
                        <td>${incident.id}</td>
                        <td>${incident.crime_type}</td>
                        <td>${incident.location.address || 'N/A'}</td>
                        <td>${incident.status}</td>
                        <td>${incident.created_at}</td>
                        <td>${incident.user ? incident.user.name : 'Anonymous'}</td>
                    </tr>
                `;
            });
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        reportResults.innerHTML = html;
    }

    // Export buttons
    const exportPdfBtn = document.getElementById('exportPdfBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');

    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', exportToPdf);
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', exportToCsv);
    }

    function exportToPdf() {
        // Implement PDF export using jsPDF
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        if (!window.reportData) {
            alert('No report data available to export.');
            return;
        }

        // Add title
        doc.setFontSize(18);
        doc.text('Incident Report', 14, 15);

        // Add date
        const now = new Date();
        doc.setFontSize(11);
        doc.text(`Generated on: ${now.toLocaleDateString()}`, 14, 25);

        let y = 35;

        // Add summary statistics table
        doc.setFontSize(14);
        doc.text('Summary Statistics', 14, y);
        y += 6;

        const summaryData = [
            ['Metric', 'Value'],
            ['Total Incidents', window.reportData.summary.total_incidents],
            ['Resolution Rate', window.reportData.statistics.resolution_rate + '%']
        ];

        doc.autoTable({
            startY: y,
            head: [summaryData[0]],
            body: summaryData.slice(1),
            theme: 'grid',
            styles: { fontSize: 10 },
            headStyles: { fillColor: [79, 70, 229] }
        });

        y = doc.lastAutoTable.finalY + 10;

        // Add incidents by status table
        if (window.reportData.summary.by_status) {
            doc.setFontSize(14);
            doc.text('Incidents by Status', 14, y);
            y += 6;

            const statusData = [['Status', 'Count']];
            for (const [status, count] of Object.entries(window.reportData.summary.by_status)) {
                statusData.push([status, count.toString()]);
            }

            doc.autoTable({
                startY: y,
                head: [statusData[0]],
                body: statusData.slice(1),
                theme: 'grid',
                styles: { fontSize: 10 },
                headStyles: { fillColor: [79, 70, 229] }
            });

            y = doc.lastAutoTable.finalY + 10;
        }

        // Add incidents by crime type table
        if (window.reportData.summary.by_crime_type) {
            doc.setFontSize(14);
            doc.text('Incidents by Crime Type', 14, y);
            y += 6;

            const crimeTypeData = [['Crime Type', 'Count']];
            for (const [crimeType, count] of Object.entries(window.reportData.summary.by_crime_type)) {
                crimeTypeData.push([crimeType, count.toString()]);
            }

            doc.autoTable({
                startY: y,
                head: [crimeTypeData[0]],
                body: crimeTypeData.slice(1),
                theme: 'grid',
                styles: { fontSize: 10 },
                headStyles: { fillColor: [79, 70, 229] }
            });

            y = doc.lastAutoTable.finalY + 10;
        }

        // Add incidents by officer table
        if (window.reportData.summary.by_officer) {
            doc.setFontSize(14);
            doc.text('Incidents by Officer', 14, y);
            y += 6;

            const officerData = [['Officer', 'Count']];
            for (const [officer, count] of Object.entries(window.reportData.summary.by_officer)) {
                officerData.push([officer, count.toString()]);
            }

            doc.autoTable({
                startY: y,
                head: [officerData[0]],
                body: officerData.slice(1),
                theme: 'grid',
                styles: { fontSize: 10 },
                headStyles: { fillColor: [79, 70, 229] }
            });

            y = doc.lastAutoTable.finalY + 10;
        }

        // Add detailed incidents table
        if (window.reportData.incidents && window.reportData.incidents.length > 0) {
            doc.setFontSize(14);
            doc.text(`Detailed Incidents (${window.reportData.incidents.length})`, 14, y);
            y += 6;

            const incidentData = [['ID', 'Crime Type', 'Location', 'Status', 'Date', 'User']];
            window.reportData.incidents.forEach(incident => {
                incidentData.push([
                    incident.id.toString(),
                    incident.crime_type,
                    incident.location.address || 'N/A',
                    incident.status,
                    incident.created_at,
                    incident.user ? incident.user.name : 'Anonymous'
                ]);
            });

            doc.autoTable({
                startY: y,
                head: [incidentData[0]],
                body: incidentData.slice(1),
                theme: 'grid',
                styles: { fontSize: 8 },
                headStyles: { fillColor: [79, 70, 229] },
                columnStyles: {
                    2: { cellWidth: 40 },
                    5: { cellWidth: 30 }
                }
            });
        }

        doc.save('incident_report.pdf');
    }

    function exportToCsv() {
        // Implement CSV export
        let csvContent = "data:text/csv;charset=utf-8,";
        
        // Add headers
        csvContent += "ID,Crime Type,Location,Status,Date,User\n";
        
        // Add data rows
        const rows = document.querySelectorAll('#detailedIncidentsTable tbody tr');
        rows.forEach(row => {
            const cols = row.querySelectorAll('td');
            const rowData = Array.from(cols).map(col => `"${col.textContent.trim()}"`).join(',');
            csvContent += rowData + "\n";
        });
        
        // Create download link
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", "incident_report.csv");
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
});

