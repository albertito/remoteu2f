
// This function gets called when the security key gives us a response to our
// register/sign request.
function handleKeyResponse(resp) {
    if (resp.errorCode != undefined && resp.errorCode != u2f.ErrorCodes.OK) {
        codeToText = {
            0: "OK",
            1: "General error (hardware issues?)",
            2: "Bad request (please report)",
            3: "Unsupported configuration (please report)",
            4: "Device ineligible, did you forget to register it?",
            5: "Timed out waiting for security key",
        }

        $("div#icon").toggleClass("pulse", false);
        $("span#icon").text(" ✘ ");
        $('#status').text(
                codeToText[resp.errorCode] + " -- "
                + resp.errorMessage);
        return;
    }

    $("span#icon").text(" ○ ○ ○ ");
    $('#status').text('sending response');
    $.post('response', JSON.stringify(resp)).done(function() {
        $("div#icon").toggleClass("pulse", false);
        $("span#icon").text(" ✔ ");
        $('#status').text('done');

    });
}
