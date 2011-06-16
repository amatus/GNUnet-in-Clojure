// Returns a function which will return immedatly and execute f later.
// This should be used for any functions called by the applet to avoid
// deadlocks.
// TODO: stop using setTimeout once IE supports other methods.
// Stop using this all together when Icedtea supports asynchronous calls.
function deferCallback(context, f) {
  return function() {
    var args = arguments;
    setTimeout(function() { f.apply(context, args); }, 0);
  }
}

// Called from the applet when it is ready.
gnunetInit = function() {
  deferCallback(gnunetReady, gnunetReady.resolve)();
}

$(function() {
  // Create deferred object which is resolved when the applet is ready.
  window.gnunetReady = $.Deferred();
  // Create the applet console.
  var term = $('<div></div>')
    .terminal(
      function() { term.error('Applet not initialized'); },
      {name:'norepl',
       prompt:'',
       greetings:'Loading...',
       enabled:false,
       exit:false,
       cookie:false});
  gnunetReady.done(
    function() {
      var input = gnunet.repl(
        function(str) {
          str = String(str);
          if(str.match('\n$'))
            term.echo(str);
          else
            term.set_prompt($.trim(str));
        },
        function(str) { term.error(String(str)); });
      term.push(
        function(str) {
          term.set_prompt('');
          gnunet.write(input, str + '\n');
        },
        {name:'repl',
         greeting:'',
         prompt:''});
    });
  // Wrap the applet console in a dialog box.
  var repl = term.dialog(
    {autoOpen:false,
     height:400,
     width:600,
     title:'Applet Console',
     close:function() { term.disable(); }});
  // Open the dialog box when ` is pressed, like Quake.
  $(document.documentElement).keypress(
    function(e) {
      if(e.which != 96)
        return true;
      target = $(e.target);
      if(target.is('input') || target.is('textarea') || target.is('select'))
        return true;
      term.enable();
      repl.dialog('open');
    });
  // Configure and start GNUnet peer
  window.peerReady = $.Deferred();
  var peerCallback = function(peer) {
    if(peer == null) {
      $('#status').html('Unable to start peer!');
      peerReady.reject();
      return;
    }
    if(peer == "badkey") {
      generateKey();
      return;
    }
    peerReady.resolve(peer);
  }
  var startPeer = function(key) {
    localStorage.setItem('v1 peer.key', key);
    $('#status').html('Starting peer...');
    gnunet.startPeer(key, deferCallback(null, peerCallback));
  }
  var generateKey = function() {
    $('#status').html('Generating peer identity...');
    gnunet.generateKey(deferCallback(null, startPeer));
  }
  gnunetReady.done(
    function() {
      var key = localStorage.getItem('v1 peer.key');
      if(key == null) {
        generateKey();
      } else {
        startPeer(key);
      }
    });
  // now what?
  var peerWatcher = function(peer, json) {
    var delta = $.parseJSON(String(json));
    var peerTable = $('#peers > tbody');
    if(delta.peersRemoved) {
      $.each(delta.peersRemoved, function(i, p) {
        peerTable.remove('#' + p);
      });
    }
    if(delta.peersAdded) {
      $.each(delta.peersAdded, function(i, p) {
        peerTable.remove('#' + p);
        peerTable.append(
          '<tr id="' + p + '"><td><pre>' + p + '</pre></td></tr>');
      });
    }
    var changesList = $('#changes > li:last');
    if(delta.peerChanged) {
      changesList.append('<li>' + String(delta.peerChanged)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        + '</li>');
    }
  }
  peerReady.done(
    function(peer) {
      $('#status').html('Peer running');
      gnunet.watchPeers(peer, deferCallback(null,
        function(json) { peerWatcher(peer, json); }));
      gnunet.configureTCP(peer, 2086);
      gnunet.fetchHostlist(peer, "http://v9.gnunet.org:58080");
    });
});

// Functions to aid debugging from the applet console
// run: (jscall-wait *applet* "function name" arg1 arg2 argn)
function getPeer() {
  var peer;
  if (!peerReady.isResolved())
    return null;
  peerReady.done(function(p) { peer = p; });
  return peer;
}
