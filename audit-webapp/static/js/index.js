$(function() {
  var update = function(id) {
    $.ajax({
      'url': id + '/status',
      'dataType': 'json',
      'cache': false,
      'success': function(data) {
        $('#progressbar').removeClass('progress-bar-warning');
        if (data['done']) {
          $('#progressbar').css('width', '100%');
          $('#progressbar').addClass('progress-bar-success');
          $('#progressbar_status').text('Complete!');
          location.href = id + '/';
        } else {
          $('#progressbar').css('width', data['progress'] + '%');
          $('#progressbar_status').text(data['status']);
          setTimeout(function() {
            update(id);
          }, 500);
        }
      },
      'error': function() {
        $('#progressbar').addClass('progress-bar-warning');
        setTimeout(function() {
          update(id);
        }, 500);
      }
    });
  }

  $('.datepicker').datepicker({
    'format': 'yyyy-mm-dd'
  });

  $('#auditgen').submit(function(e) {
    $('#processingmodal').modal('show');
    e.preventDefault();
    $.ajax({
      'type': 'POST',
      'url': 'create',
      'data': {
        'startdate': $('#startdate').val(),
        'enddate': $('#enddate').val(),
        'ruleset': $('#ruleset').val()
      },
      'success': function(id) {
        $('#jobid').text(id);
        update(id);
      },
      'error': function() {
        $('#progressbar')
          .addClass('progress-bar-striped progress-bar-danger')
          .css('width', '100%');
        $('#progressbar_status').text('Could not create job');
      },
      'dataType': 'text'
    });
  });

  $('#attach').click(function(e) {
    e.preventDefault();
    var id = prompt("Job ID");
    $('#processingmodal').modal('show');
    $('#progressbar_status').text('Trying to attach to job');
    update(id);
  });
});
