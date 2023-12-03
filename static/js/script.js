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
                   "<td>" + info.Info + "</td>" +
                   "</tr>";

    document.getElementById("dns_packets").innerHTML += tableRow;
});