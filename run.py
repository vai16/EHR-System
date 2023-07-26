from server import *

# Starting the python applicaiton
if __name__ == '__main__':
    print("-"*70)
    print("""Web Server Started!: http://127.0.0.1:"""+portchoice+"""/""")
    print("-"*70)
    page = {'title' : 'Electronic Health Record System'}
    app.run(debug=True, host='0.0.0.0', port=int(portchoice))
