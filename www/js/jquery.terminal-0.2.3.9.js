/*!
 * JQuery Terminal Emulator Plugin
 * Copyright (C) 2010 Jakub Jankiewicz <http://jcubic.pl> 
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*

     TODO:
           fix cursor move in command longer then terminal width
           fix resize issue in text that was echoed earlier
           terminal must store list of lines that have bean echoed
           and when terminal is resized every longer line must be splited
           and putted in div
           remove access to command_line from outside of terminal
           add self.read method this will reduce the code for login
           
           
             if (command == 'foo') {
                var end = false;
                while (!end) {
                   term.read("type foo:", function(str) {
                      // process str
                      end = true;
                   }, {mask:true}); // or passed as single value
                }
           Bash have "read x; echo $x"

           or simply add mask method and users can handle 
           inputs by themself
           if (command == 'passwd') {
               term.set_prompt('password:');
               term.echo('enter password');
               term.mask(true);
               process_passwd = true;
           } else if (process_passwd) {
               if (change_passwd(command)) {
                   term.echo('password changed');
               }
               term.mask(false);
           }
           
           add support for - $(...).each(function() { ... });
           add destroy method to terminal
           add suport for clipboard
           add echo function without new line


$.fn.pluginname = function(options) {
   var settings = $.extend({}, $.fn.pluginname.defaultOptions, options);

   return this.each(function() {
      var $this = $(this);
   });
};

$.fn.pluginname.defaultOptions = {
};

*/

Array.prototype.has = function(val) {
    for (var i=this.length; i--;) {
        if (this[i] == val) {
            return true;
        }
    }
    return false;
};

(function($, undefined) {

    // -----------------------------------------------------------------------
    /*
    function decodeHTML(str) {
        if (typeof str == 'string') {
            str = str.replace(/&amp;/g, '&');
            str = str.replace(/&lt;/g, '<').replace(/&gt;/g, '>');
            str = str.replace(/&#09;/g, '\t');
            str = str.replace(/<br\/?>/g, '\n').replace(/&nbsp;/g, ' ');
            return str;
        } else {
            return '';
        }
    }
    */
    function str_parts(str, length) {
        var result = [];
        var len = str.length;
        if (len < length) {
            return [str];
        }
        for (var i=0; i<len; i+=length) {
            result.push(str.substring(i, i+length));
        }
        return result;
    }
    // -----------------------------------------------------------------------
    function encodeHTML(str) {
        if (typeof str == 'string') {
            str = str.replace(/&/g,'&amp;');
            str = str.replace(/</g,'&lt;').replace(/>/g,'&gt;');
            str = str.replace(/\n/g, '<br/>');
            str = str.replace(/ /g, '&nbsp;');
            // only more than one space replace by &nbsp; to allow wrap of
            // long lines
            str = str.replace(/ (?= )/g, '&nbsp;');
            str = str.replace(/\t/g, '&#09;');
            // restrict to visible ASCII characters, #32-#126. 
            str = str.replace(/[^ -~]/g, '');
            return str;
        } else {
            return '';
        }
    }
    // -----------------------------------------------------------------------
    // CYCLE DATA STRUCTURE
    // -----------------------------------------------------------------------
    function Cycle(init) {
        var data = init ? [init] : [];
        var pos = 0;
        $.extend(this, {
            rotate: function() {
                if (data.length == 1) {
                    return data[0];
                } else {
                    if (pos == data.length-1) {
                        pos = 0;
                    } else {
                        ++pos;
                    }
                    return data[pos];
                }
            },
            length: function() {
                return data.length;
            },
            set: function(item) {
                for (var i=data.length; i--;) {
                    if (data[i] === item) {
                        pos = i;
                        return;
                    }
                }
                this.append(item);
            },
            front: function() {
                return data[pos];
            },
            append: function(item) {
                data.push(item);
            }
        });
    }
    // -----------------------------------------------------------------------
    // :: BCYCLE DATA STRUCTURE // Two way cycle
    // -----------------------------------------------------------------------
    function BCycle(init) {
        var data = init instanceof Array ? init : init ? [init] : [];
        var pos = 0;
        $.extend(this, {
            left: function() {
                if (pos === 0) {
                    pos = data.length-1;
                } else {
                    --pos;
                }
                return data[pos];
            },
            right: function() {
                if (pos == data.length-1) {
                    pos = 0;
                } else {
                    ++pos;
                }
                return data[pos];
            },
            current: function() {
                return data[pos];
            },
            data: function() {
                return data;
            },
            append: function(item) {
                data.push(item);
                pos = 0;
            }});
    }
    // -----------------------------------------------------------------------
    // :: STACK DATA STRUCTURE
    // -----------------------------------------------------------------------
    function Stack(init) {
        var data = init ? [init] : [];
        $.extend(this, {
            size: function() {
                return data.length;
            },
            pop: function() {
                if (data.length === 0) {
                    return null;
                } else {
                    var value = data[data.length-1];
                    data = data.slice(0, data.length-1);
                    return value;
                }
            },
            push: function(value) {
                data = data.concat([value]);
                return value;
            },
            top: function() {
                return data.length>0 ? data[data.length-1] : null;
            }});
    }
    // serialize object myself (biwascheme or prototype library do something wiked with 
    // JSON serialization for Arrays)
    function json_stringify(object, level) {
        var result = '';
        level = level === undefined ? 1 : level;
        var type = typeof object;
        switch (type) {
        case 'function':
            result += object;
            break;
        case 'boolean':
            result += object ? 'true' : 'false';
            break;
        case 'object':
            if (object === null) {
                result += 'null';
            } else if (object instanceof Array) {
                result += '[';
                var len = object.length;
                for (var i=0; i<len-1; ++i) {
                    result += json_stringify(object[i], level+1);
                }
                result += json_stringify(object[len-1], level+1) + ']';
            } else {
                result += '{';
                for (var property in object) {
                    if (object.hasOwnProperty(property)) {
                        result += '"' + property + '":' +
                            json_stringify(object[property], level+1);
                    }
                }
                result += '}';
            }
            break;
        case 'string':
            var str = object;
            var repl = {
                '\\\\': '\\\\',
                '"': '\\"',
                '/': '\\/',
                '\\n': '\\n',
                '\\r': '\\r',
                '\\t': '\\t'};
            for (var i in repl) {
                if (repl.hasOwnProperty(i)) {
                    str = str.replace(new RegExp(i, "g"), repl[i]);
                }
            }
            result += '"' + str + '"';
            break;
        case 'number':
            result += String(object);
            break;
        }
        result += (level > 1 ? ',' : '');
        if (level == 1) {
            // last colon fix
            result = result.replace(/,([\]}])/g, '$1');
        }
        return result;
    }
    $.json_stringify = json_stringify;
    // -----------------------------------------------------------------------
    // :: HISTORY CLASS
    // -----------------------------------------------------------------------
    function History(name, cookie) {
        var enabled = true;
        if (typeof name === 'string' && name !== '') {
            name += '_';
        }
        //default cookie are on
        cookie = cookie === undefined || cookie;
        var data = cookie ? $.cookie(name + 'commands') : null;
        var bc = new BCycle(data ? eval("(" + data + ")") : ['']);

        $.extend(this, {
            append: function(item) {
                if (enabled && bc.current() != item) {
                    bc.append(item);
                    if (cookie) {
                        $.cookie(name + 'commands', json_stringify(bc.data()));
                    }
                }
            },
            data: function() {
                return bc.data();
            },
            next: function() {
                return bc.right();
            },
            previous: function() {
                return bc.left();
            },
            clear: function() {
                bc = new BCycle();
                if (cookie) {
                    $.cookie(name + 'commands', null);
                }
            },
            enable: function() {
                enabled = true;
            },
            disable: function() {
                enabled = false;
            }});
    }
    // -----------------------------------------------------------------------
    // :: COMMAND LINE PLUGIN
    // ----------------------------------------------------------------------- 
    $.fn.cmd = function(options) {
        var self = this;
        self.addClass('cmd');
        self.append('<span class="prompt"></span><span></span>' +
                    '<span class="cursor">&nbsp;</span><span></span>');
        
        var clip = $('<textarea/>').addClass('clipboard').appendTo(self);
        if (options.width) {
            self.width(options.width);
        }
        var num_chars; // calculates by draw_prompt
        var prompt_len;
        
        var mask = options.mask || false;
        var command = '';
        var position = 0;
        var prompt;
        var enabled = options.enabled;
        var name, history;

        var blink = (function() {
            var cursor = self.find('.cursor');
            return function(i) {
                cursor.toggleClass('inverted');
            };
        })();

        
        function change_num_chars() {
            self.append('<span class="__test">&nbsp;</span>');
            var test = self.find('.__test');
            num_chars = Math.floor(self.width() / test.width());
            test.remove();
        }
        function get_splited_command_line() {
            var first = command.substring(0, num_chars-prompt_len-1);
            var rest = command.substring(num_chars-prompt_len-1);
            return [first].concat(str_parts(rest, num_chars));
        }
        var redraw = (function(self) {
            var cursor = self.find('.cursor');
            var before = cursor.prev();
            var after = cursor.next();
            return function() {
                var string = mask ? command.replace(/./g, '*') : command;
                self.find('div').remove();
                before.html('');
                if (string.length > num_chars-prompt_len-1) {
                    var array = get_splited_command_line();
                    var len = array.length;
                    for (var i=0; i<len-1; ++i) {
                        before.before('<div>' + encodeHTML(array[i]) + '</div>');
                    }
                    string = array[len-1];
                }
                if (string === '') {
                    before.html('');
                    cursor.html('&nbsp;');
                    after.html('');
                } else if (position == command.length) {
                    before.html(encodeHTML(string));
                    cursor.html('&nbsp;');
                    after.html('');
                } else {
                    if (position === 0) {
                        before.html('');
                        //fix for tilda in IE
                        cursor.html(string.slice(0, 1));
                        //cursor.html(encodeHTML(string[0]));
                        after.html(encodeHTML(string.slice(1)));
                    } else {
                        var before_str = encodeHTML(string.slice(0, position));
                        before.html(before_str);
                        //fix for tilda in IE
                        var c = string.slice(position, position+1);
                        //cursor.html(string[position]));
                        cursor.html(encodeHTML(c));
                        if (position == string.lenght-1) {
                            after.html('');
                        } else {
                            after.html(encodeHTML(string.slice(position+1)));
                        }
                    }
                }
                //browser don't display last single space before and after the cursor span
                before.html(before.html().replace(/ $/, '&nbsp;'));
                after.html(after.html().replace(/^ /, '&nbsp;'));
            };
        })(self);
        
        var draw_prompt = (function() {
            var prompt_node = self.find('.prompt');
            return function() {
                if (typeof prompt == 'string') {
                    prompt_len = prompt.length;
                    prompt_node.html(encodeHTML(prompt) + '&nbsp;');
                } else {
                    prompt(function(string) {
                        prompt_len = string.length;
                        prompt_node.html(encodeHTML(string) + '&nbsp;');
                    });
                }
                change_num_chars();
            };
        })();
        var keyboard_event = (function() {
            //var prompt_node = self.find('.prompt');
            return function(e) {
                if (enabled) {
                    var pos, len;
                    if (e.keyCode == 13) {
                        //remove trailing spaces
                        command = command.replace(/\s*(.*)\s*$/mg, '$1');
                        if (history && command) {
                            history.append(command);
                        }
                        var tmp = command;
                        self.set('');
                        if (typeof prompt == 'function') {
                            draw_prompt();
                        }
                        if (options.commands) {
                            options.commands(tmp);
                        }
                    } else if (e.which == 32) { //space
                        append(' ');
                    } else if (e.which == 8) { //backspace
                        if (command !== '' && position > 0) {
                            command = command.slice(0, position-1) +
                                command.slice(position, command.length);
                            --position;
                            redraw();
                        }
                    } else if (e.which == 46) { //DELETE
                        if (command !== '' && position < command.length) {
                            command = command.slice(0, position) +
                                command.slice(position+1, command.length);
                            redraw();
                        }
                    } else if (history && e.which == 38 ||
                               (e.which == 80 && e.ctrlKey)) {
                        //UP ARROW or CTRL+P
                        self.set(history.previous());
                    } else if (history && e.which == 40 ||
                               (e.which == 78 && e.ctrlKey)) {
                        //DOWN ARROW or CTRL+N
                        self.set(history.next());
                    } else if (e.which == 27) { //escape
                        self.set('');
                    } else if (e.which == 37 ||
                               (e.which == 66 && e.ctrlKey)) { 
                        //LEFT ARROW or CTRL+B
                        if (e.ctrlKey && e.which != 66) {
                            len = position-1;
                            pos = 0;
                            if (command[len] == ' ') {
                                --len;
                            }
                            for (var i=len; i>0; --i) {
                                if (command[i] == ' ' && command[i+1] != ' ') {
                                    pos = i+1;
                                    break;
                                }
                            }
                            self.position(pos);
                        } else {
                            if (position > 0) {
                                --position;
                                redraw();
                            }
                        }
                    } else if (e.which == 39 || 
                               (e.which == 70 && e.ctrlKey)) {
                        //RIGHT ARROW OR CTRL+F
                        if (e.ctrlKey && e.which != 70) {
                            pos = position;
                            len = command.length;
                            if (command[pos] == ' ') {
                                ++pos;
                            }
                            for (var i=pos; i<len; ++i) {
                                if ((command[i] == ' ' && command[i-1] != ' ' ) || 
                                    i==len-1) {
                                    pos = i;
                                    break;
                                }
                            }
                            position = pos;
                            redraw();
                        } else {
                            if (position < command.length) {
                                ++position;
                                redraw();
                            }
                        }
                    } else if (e.which == 123) { //F12 - Allow Firebug
                        return true;
                    } else if (e.which == 36) { //HOME
                        self.position(0);
                    } else if (e.which == 35) {
                        //END
                        self.position(command.length);
                    } else if (e.metaKey) {
                        if (e.shiftKey) { // CTRL+SHIFT+??
                            if (e.which == 84) {
                                //CTRL+SHIFT+T open closed tab
                                return true;
                            }
                        } else if (e.altKey) { //ALT+CTRL+??
                            //return true;
                        } else {
                            //NOTE: in opera charCode is undefined
                            if (e.which == 65) {
                                //CTRL+A
                                self.position(0);
                            } else if (e.which == 69) {
                                //CTRL+E
                                self.position(command.length);
                            } else if (e.which == 88 || e.which == 67 ||
                                       e.which == 87 || e.which == 84) {
                                //CTRL+X CTRL+C CTRL+W CTRL+T CTRL+T
                                return true;
                            } else if (e.which == 86) {
                                //CTRL+V
                                clip.focus();
                                window.setTimeout(function() {
                                    var content = clip.val();
                                    if (position == command.length) {
                                        command += content;
                                    } else if (position === 0) {
                                        command = content + command;
                                    } else {
                                        command = command.slice(0, position) +
                                            content + command.slice(postion);
                                    }
                                    position += content.length;
                                    redraw();
                                    clip.val('');
                                }, 1);
                                return true;
                            } else if (e.which == 75) { 
                                //CTRL+K
                                if (position === 0) {
                                    self.set('');
                                } else if (position != command.length) {
                                    self.set(command.slice(0, position));
                                }
                            } else if (e.which == 70) { //CTRL+F find
                                return true;
                            } else if (e.which == 17) { //CTRL+TAB switch tab
                                return true;
                            }
                        }
                    } else if (e.altKey) {
                        //if (e.which == 18) { // press ALT
                        if (e.which == 68) { //ALT+D
                            pos = position;
                            len = command.length;
                            var space = null;
                            for (var i=pos; i<len; ++i) {
                                if (command[i] == ' ') {
                                    space = i+1;
                                    break;
                                }
                            }
                            if (space) {
                                command = command.slice(0, pos) +
                                    command.slice(space);
                            } else {
                                command = command.slice(0, pos);
                            }
                            redraw();
                        }
                    } else {
                        return true;
                    }
                    return false;
                }
            };
            
        })();
        
        function append(c) {
            if (position == command.length) {
                command += c;
            } else {
                command = command.slice(0, position) + c +
                    command.slice(position);
            }
            ++position;
            redraw();
        }
        

        $.extend(self, {
            name: function(string) {
                if (string !== undefined) {
                    name = string;
                    history = new History(string, options.cookie);
                } else {
                    return name;
                }
            },
            history: function() {
                return history;
            },
            set: function(string) {
                if (string !== undefined) {
                    command = string;
                    position = command.length;
                    redraw();
                }
            },
            commands: function(commands) {
                if (commands) {
                    options.commands = commands;
                } else {
                    return commands;
                }
            },
            destroy: function() {
                $(document.documentElement).unbind('.command_line');
                self.find('.prompt').remove();
            },
            prompt: function(user_prompt) {
                if (user_prompt === undefined) {
                    return prompt;
                } else {
                    if (typeof user_prompt == 'string' || 
                        typeof user_prompt == 'function') {
                        prompt = user_prompt;
                    } else {
                        throw "prompt must be a function or string";
                    }
                    draw_prompt();
                }
            },
            position: function(n) {
                if (typeof n == 'number') {
                    position = n;
                    redraw();
                } else {
                    return position;
                }
            },
            resize: function() {
                change_num_chars();
                redraw();
            },
            enable: function() {
                self.everyTime(500, 'blink', blink);
                enabled = true;
            },
            isenabled: function() {
                return enabled;
            },
            disable: function() {
                self.stopTime('blink', blink);
                self.find('.cursor').removeClass('inverted');
                enabled = false;
            },
            mask: function(display) {
                if (typeof display == 'boolean') {
                    mask = display;
                    redraw();
                } else {
                    return mask;
                }
            }
        });
        
        // INIT
        self.name(options.name || '');
        prompt = options.prompt || '>';
        draw_prompt();
        
        
        if (options.enabled === undefined && !options.enabled) {
            self.enable();
        }
        // Keystrokes
        $(document.documentElement).keypress(function(e) {
            if (enabled) {
                if ([38, 32, 13, 40, 0, 8].has(e.which) &&
                    !(e.which == 40 && e.shiftKey)) {
                    return false;
                } else if (!(e.ctrlKey || e.altKey)) {
                    append(String.fromCharCode(e.which));
                }
            }
        }).keydown(keyboard_event);
        // characters
        return self;
    };
    // -----------------------------------------------------------------------
    // JSON-RPC CALL
    // -----------------------------------------------------------------------
    $.jrpc = function(url, id, method, params, success, error) {
        var request = json_stringify({
	    'jsonrpc': '2.0', 'method': method,
            'params': params, 'id': id});
        //terminals.front().echo(request);
        return $.ajax({
            url: url,
            data: request,
            /*success: function(response) {
            terminals.front().echo(JSON.stringify(response));
            success(response);
            },*/
            success: success,
            error: error,
            contentType: 'application/json',
            dataType: 'json',
            async: true,
            cache: false,
	        //timeout: 1,
            type:"POST"});
    };
    // -----------------------------------------------------------------------
    // :: TERMINAL PLUGIN CODE
    // -----------------------------------------------------------------------
    //list of terminals global in this scope
    var terminals = new Cycle();

    $.fn.terminal = function(init_eval, options) {
        
        var self = this;
        if (self.length === 0) {
            throw 'Sorry, but terminal said that "' + self.selector +
                '" is not valid selector';
        }
        if (self.data('terminal')) {
            return self.data('terminal');
        }
        self.addClass('terminal');
        
        var settings = {
            name: null,
            greetings: "Wellcome to JQuery Terminal Emulator\n"+
            "Copyright (C) 2010 Jakub Jankiewicz <http://jcubic.pl>",
            prompt: '>',
            history: true,
            cookie: true,
            exit: true,
            enabled: true,
            login: null
        };

        var terminal_id = (function() {
            return terminals.length();
        })();

        if (options) {
            if (options.width) {
                self.width(options.width);
            }
            if (options.height) {
                self.height(options.height);
            }
            $.extend(settings, options);
        }

        self.css('overflow', 'hidden');
        self.append('<div class="terminal-output"></div><div></div>');
        
        function get_num_chars() {
            self.find('.terminal-output').append('<span class="__test">&nbsp;</span>');
            var test = self.find('.__test');
            var result = Math.floor(self.width() / test.width());
            test.remove();
            return result;
        }

        //numer of chars in line
        var num_chars = get_num_chars();

        // display Exception on terminal
        function display_exception(e, label) {
            if (typeof e == 'string') {
                self.echo('[' + label + ']: ' + e).addClass('error');
            } else {
                //display filename and line which throw exeption
                self.echo('[' + label + ']: ' + e.fileName + ': ' + e.message).addClass('error');
                self.pause();
                $.get(e.fileName, function(file) {
                    self.resume();
                    self.echo('[' + e.lineNumber + ']' +
                              file.split('\n')[e.lineNumber-1]).addClass('error');
                });
            }
        }

        //validating if object is string or function, call that function and
        //display exeption if any
        function valid(label, object) {
            try {
                if (typeof object == 'function') {
                    object(function() {
                        // don't care
                    });
                } else if (typeof object != 'string') {
                    var msg = label + " must be string or function";
                    throw msg;
                }
            } catch (e) {
                display_exception(e, label.toUpperCase());
                return false;
            }
            return true;
        }

        // ----------------------------------------------------------
        // TERMINAL METHODS
        (function() {
            var pause = !settings.enabled;
            var output = self.find('.terminal-output');
            function scroll_to_bottom(terminal) {
                terminal.scrollTop(self.attr("scrollHeight"));
            }
            $.extend(self, {
                clear: function() {
                    output.html('');
                    self.command_line.set('');
                    self.attr({ scrollTop: 0});
                },
                paused: function() {
                    return pause;
                },
                pause: function() {
                    if (self.command_line) {
                        self.disable();
                        self.command_line.hide();
                    }
                },
                resume: function() {
                    if (self.command_line) {
                        self.enable();
                        self.command_line.show();
                        scroll_to_bottom(self);
                    }
                },
                resize: function(width, height) {
                    self.width(width);
                    self.height(height);
                    scroll_to_bottom(self);
                    num_chars = get_num_chars();
                    self.command_line.resize();
                },
                focus: function(toggle) {
                    if (terminals.length() == 1) {
                        self.oneTime(100, function() {
                            if (toggle === undefined || toggle) {
                                terminals.front().enable();
                            } else {
                                terminals.front().disable();
                            }
                        });
                    } else if (terminals.length() > 0) {
                        if (toggle === undefined || toggle) {
                            if (terminals.front() === self) {
                                self.enable();
                            } else {
                                terminals.front().disable();
                                terminals.set(self);
                                self.enable();
                            }
                            scroll_to_bottom(self);
                        } else {
                            self.disable();
                            //delay enabling next terminal (NOTE: when using
                            //single keypress to switch between terminals 
                            //that character was put on next terminal)
                            self.oneTime(100, function() {
                                terminals.rotate().enable();
                                scroll_to_bottom(terminals.front());
                            });
                        }
                    }
                },
                enable: function() {
                    if (self.command_line) {
                        self.command_line.enable();
                        pause = false;
                    }
                },
                disable: function() {
                    if (self.command_line) {
                        pause = true;
                        self.command_line.disable();
                    }
                },
                set_prompt: function(prompt) {
                    if (valid('prompt', prompt)) {
                        self.command_line.prompt(prompt);
                    }
                },
                echo: function(object, options) {
                    var string = typeof object == 'string' ? object : String(object);
                    var div;
                    if (options && options.raw) {
                        div = $('<div>' + string + '</div>');
                    } else if (string.length > num_chars) {
                        var array = string.split('\n'); // string can have line break
                        div = $('<div></div>');
                        var len = array.length;
                        for (var i=0; i<len; ++i) {
                            if (array[i] === '' || array[i] == '\r') { 
					            div.append('<div>&nbsp;</div>');
				            } else {
                                if (array[i].length > num_chars) { // if line is longer then width
                                    $.each(str_parts(array[i], num_chars), function(i, string) {
                                        div.append('<div>' + encodeHTML(string) + '</div>');
                                    });
                                } else {
                                    div.append('<div>' + encodeHTML(array[i]) + '</div>');
                                }
                            }
                        }
                    } else {
                        div = $('<div>' + encodeHTML(string) + '</div>');
                    }
                    output.append(div);
                    div.width('100%');
                    scroll_to_bottom(self);
                    return div;
                },
                error: function(message) {
                    return self.echo(message).addClass('error');
                },
                scroll: function(amount) {
                    if (amount > self.attr('scrollTop') && amount > 0) {
                        self.attr('scrollTop', 0);
                    }
                    var pos = self.attr('scrollTop');
                    self.attr('scrollTop', pos+amount);
                },
                logout: settings.login ? function() {
                    while (interpreters.size() > 1) {
                        interpreters.pop();
                    }
                    logout();
                } : function () {
                    throw "You don't have login function";
                },
                token: settings.login ? function() {
                    return $.cookie('token' + (settings.name ? '_' + settings.name : ''));
                } : null,
                login_name: settings.login ? function() {
                    return $.cookie('login_' + (settings.name ? '_' + settings.name : ''));
                } : null,
                name: function() {
                    return settings.name;
                },
                push: function(_eval, options) {
                    if (!options.prompt || valid('prompt', options.prompt) && 
                        (options.greetings !== null || options.preetings !== false || 
                         valid('greetings', options.greetings))) {
                        if (typeof _eval == 'string') {
                            _eval = make_json_rpc_eval_fun(options['eval'], self);
                        }
                        interpreters.push({
                            name: options.name,
                            'eval': _eval,
                            prompt: options.prompt,
                            login: options.login,
                            greetings: options.greetings});
                        if (options.login) {
                            login();
                        } else {
                            prepare_top_interpreter(true);
                        }
                    }
                },
                pop: function() {
                    echo_command('');
                    if (interpreters.top().name === settings.name) {
                        if (settings.login) {
                            logout();
                        } else {
                            return null;
                        }
                    } else {
                        var current = interpreters.pop();
                        prepare_top_interpreter();
                        return current;
                    }
                }
            });
        })();

        //function constructor for eval
        function make_json_rpc_eval_fun(url, terminal) {
            var id = 1;
            var service = function(method, params) {
                terminal.pause();
                $.jrpc(url, id++, method, params, function(json) {
                    if (!json.error) {
                        if (typeof json.result == "string") {
                            terminal.echo(json.result);
                        } else if (json.result instanceof Array) {
                            terminal.echo(json.result.join(" "));
                        } else if (typeof json.result == "object") {
                            var string = "";
                            for (var f in json.result) {
                                if (json.result.hasOwnProperty(f)) {
                                    string += f + ": " + json.result[f] + "\n";
                                }
                            }
                            terminal.echo(string);
                        }
                    } else {
                        terminal.error('[RPC] ' + json.error.message);
                    }
                    terminal.resume();
                }, function(xhr, status, error) {
                    terminal.error('[AJAX] ' + status + 
                                   ' - Server reponse is: \n' + 
                                   xhr.responseText);
                    terminal.resume();
                });
            };
            //this is eval function
            return function(command, terminal) {
                if (command === '') {
                    return;
                }
                var method, params;
                if (!command.match(/[^ ]* /)) {
                    method = command;
                    params = [];
                } else {
                    command = command.split(' ');
                    method = command[0];
                    params = command.slice(1);
                }
                if (!settings.login || method == 'help') {
                    service(method, params);
                } else {
                    var token = terminal.token();
                    if (token) {
                        service(method, [token].concat(params));
                    } else {
                        terminal.error('[AUTH] Access denied (no token)');
                    }
                }
            };
        }
        
        // create json-rpc eval function
        var url;
        if (typeof init_eval == 'string') {
            url = init_eval;
            init_eval = make_json_rpc_eval_fun(init_eval, self);
        }
        
        // create json-rpc authentication function
        if (url && typeof settings.login == 'string' || url) {
            settings.login = (function(method) {
                var id = 1;
                return function(user, passwd, callback) {
                    self.pause();
                    $.jrpc(url,
                           id++,
                           method, 
                           [user, passwd],
                           function(response) {
                               self.resume();
                               if (!response.error && response.result) {
                                   callback(response.result);
                               } else {
                                   callback(null);
                               }
                           }, function(xhr, status, error) {
                               self.resume();
                               self.error('[AJAX] Response: ' + 
                                          status + '\n' + 
                                          xhr.responseText);
                           });
                };
                //default name is login so you can pass true
            })(typeof settings.login == 'boolean' ? 'login' : settings.login);
        }

        //display prompt and last command
        function echo_command(command) {
            var prompt = self.command_line.prompt();
            if (self.command_line.mask()) {
                command = command.replace(/./g, '*');
            }
            if (typeof prompt == 'function') {
                prompt(function(string) {
                    self.echo(string + ' ' + command);
                });
            } else {
                self.echo(prompt + ' ' + command);
            }
        }

        // wrapper over eval it implements exit and catch all exeptions
        // from user code and display them on terminal
        function commands(command) {
            try {
                var interpreter = interpreters.top();
                
                if (command == 'exit' && settings.exit) {
                    if (interpreters.size() == 1) {
                        if (settings.login) {
                            logout();
                        } else {
                            var msg = "You can exit from main interpeter";
                            self.echo(msg);
                        }
                    } else {
                        terminal.pop();
                    }
                } else {
                    echo_command(command);
                }
                interpreter['eval'](command, self);
            } catch (e) {
                display_exception(e, 'USER');
                throw e;
            }
        }
        
        // functions change prompt of command line to login to password
        // and call user login function with callback that set token
        // if user call it with value that is true
        function login() {
            var user = null;
            self.command_line.prompt('login:');
            // don't stor logins in history
            if (settings.history) {
                self.command_line.history().disable();
            }
            self.command_line.commands(function(command) {
                try {
                    echo_command(command);
                    if (!user) {
                        user = command;
                        self.command_line.prompt('password:');
                        self.command_line.mask(true);
                    } else {
                        self.command_line.mask(false);
                        settings.login(user, command, function(user_data) {
                            if (user_data) {
                                // if no cookie overwrite authentication methods
                                if (!settings.cookie) {
                                    self.token = function() {
                                        return user_data;
                                    };
                                    self.login = function() {
                                        return user;
                                    };
                                } else {
                                    var name = (settings.name ? '_' + settings.name : '');
                                    $.cookie('token' + name, user_data);
                                    $.cookie('login' + name, user);
                                }
                                //restore commands and run interpreter
                                self.command_line.commands(commands);
                                prepare_top_interpreter(true);
                            } else {
                                self.error('Wrong password try again');
                                self.command_line.prompt('login:');
                                user = null;
                            }
                            self.resume();
                        });
                    }
                } catch(e) {
                    display_exception(e, 'LOGIN', self);
                    throw e;
                }
            });
        }

        //logout function remove cookies disable history and run login function
        //this function is call only when options.login function is defined
        //check for this is in self.pop method
        function logout() {
            $.cookie('token' + (settings.name ? '_' + settings.name : ''), null);
            $.cookie('login_' + (settings.name ? '_' + settings.name : ''), null);
            if (settings.history) {
                self.command_line.history().disable();
            }
            login();
        }

        
        //function enable history, set prompt, run eval function 
        function prepare_top_interpreter(greetings) {
            var interpreter = interpreters.top();
            var name = '';
            if (interpreter.name !== undefined &&
                interpreter.name !== '') {
                name += interpreter.name + '_';
            }
            name += terminal_id;
            self.command_line.name(name);
            self.command_line.prompt(interpreter.prompt);
            if (settings.history) {
                self.command_line.history().enable();
            }
            self.command_line.set('');
            
            if (greetings) {
                if (typeof interpreter.greetings == 'function') {
                    try {
                        interpreter.greetings(function(user_string) {
                            self.echo(user_string);
                        });
                    } catch (e) {
                        display_exception(e, 'GREETINGS', self);
                        throw e;
                    }
                } else if (typeof interpreter.greetings == 'string') {
                    self.echo(interpreter.greetings);
                }
            }
        }

        function key_press(e) {
            if (!self.paused()) {
                if (e.charCode == 100 && e.metaKey && settings.exit) {
                    if (settings.name == interpreters.top().name && !settings.login) {
                        self.echo("you can't exit from top interpreter");
                    } else {
                        self.pop();
                    }
                    return false;
                } else if (e.charCode == 118 && e.ctrlKey) {
                    window.setTimeout(function() {
                        self.attr({scrollTop: 
                                   self.attr("scrollHeight")});
                    }, 1);
                    return true;
                } else if (e.which == 34) { // PAGE DOWN
                    self.scroll(self.height());
                } else if (e.which == 33) { // PAGE UP
                    self.scroll(-self.height());
                } else {
                    self.attr({scrollTop: self.attr("scrollHeight")});
                }
            }
        }
        // INIT CODE
        if (valid('prompt', settings.prompt) && 
            (settings.greetings !== null ||
             settings.greetings !== false ||
             valid('greetings', settings.greetings))) {
            var interpreters = new Stack({'name': settings.name,
                                          'eval': init_eval,
                                          'prompt': settings.prompt,
                                          'greetings': settings.greetings});

            self.command_line = self.find('.terminal-output').next().cmd({
                prompt: settings.prompt,
                history: settings.history,
                width: '100%',
                cookie: settings.cookie,
                commands: commands
            });

            terminals.append(self);
            if (settings.enabled) {
                self.focus();
            } else {
                self.disable();
            }
            
            self.click(self.focus);
            $(document.documentElement).keypress(key_press);
            if (self.token && !self.token() && self.login_name && !self.login_name()) {
                login();
            } else {
                prepare_top_interpreter(true);
            }
            self.mousewheel(function(event,delta){
                //self.echo(dir(event));
                if (delta > 0) {
                    self.scroll(-40);
                } else {
                    self.scroll(40);
                }
                return false;
            }, true);
        }
        self.data('terminal', self);
        return self;
    }; //terminal plugin

})(jQuery);