var socket = io.connect('http://' + document.domain + ':' + location.port);
socket.on('dns_packet', function (data) {
    var info = data.data;
    var tableRow = "<tr class='dns'>" +
                   "<td>" + info.Number + "</td>" +
                   "<td>" + info.Time + "</td>" +
                   "<td>" + info.Source + "</td>" +
                   "<td>" + info.Destination + "</td>" +
                   "<td>" + info.Protocol + "</td>" +
                   "<td>" + info.Length + "</td>" +
                   "<td class='dns_summary'>" +
                   "<div class='short_info'>" + info.Info + "</div>" +
                   "<span class='show_summary'> > All info</span>" +
                   "</td>" +
                   "</tr>";

    document.getElementById("dns_packets").innerHTML += tableRow;

    var tableRows = document.querySelectorAll('.dns'); // We recup all the rows of the table
        tableRows.forEach(function (row) {
            var summaryCell = row.querySelector('.dns_summary'); // We recup the cell of the row that contains the summary
            var showSummaryButton = summaryCell.querySelector('.show_summary'); // We recup the button that allows to show the summary
            var shortInfo = summaryCell.querySelector('.short_info'); // We recup the short summary

            showSummaryButton.addEventListener('click', function (event) {
                event.stopPropagation(); // To prevent the click event from bubbling up to the row
                var isExpanded = summaryCell.classList.toggle('expanded'); // We toggle the class 'expanded' on the cell

                var fullInfo = summaryCell.querySelector('.full_info'); // We recup the full summary
                
                // We change the text of the button depending on the state of the cell
                // We also create the full summary if it doesn't exist yet and we display it
                if (isExpanded) {
                    showSummaryButton.textContent = ' - Less info';
                    if (!fullInfo) {
                        fullInfo = document.createElement('div');
                        fullInfo.classList.add('full_info');
                        fullInfo.textContent = info.Summary;
                        summaryCell.appendChild(fullInfo);
                    } else {
                        fullInfo.style.display = 'block';
                    }
                } else {
                    showSummaryButton.textContent = ' > All info';
                    if (fullInfo) {
                        fullInfo.style.display = 'none';
                    }
                }
            });

            // Cache the full summary at the beginning
            var fullInfo = document.createElement('div');
            fullInfo.classList.add('full_info');
            fullInfo.textContent = info.Summary;
            summaryCell.appendChild(fullInfo);
            fullInfo.style.display = 'none';
        });
});