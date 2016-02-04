# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2012-2016, Ryan P. Wilson
#
#     Authority FX, Inc.
#     www.authorityfx.com

#!/usr/bin/env python

import sys
import getpass
import smtplib
import string
import imaplib
import re
from email.parser import HeaderParser, Parser
import threading
import Queue
import sqlite3
import os
import random
from hashlib import sha256
from datetime import datetime
from urllib import unquote
import base64

l_types = {'workstation':0, 'render':1, 'trial':2}

def hash_password(password):
    # Make sure password is a str because we cannot hash unicode objects
    if isinstance(password, unicode):
        password = password.encode('utf-8')
    salt = sha256()
    salt.update(os.urandom(60))
    hash = sha256()
    hash.update(password + salt.hexdigest())
    password = salt.hexdigest() + hash.hexdigest()
    # Make sure the hashed password is a unicode object at the end of the
    # process because SQLAlchemy _wants_ unicode objects for Unicode cols
    if not isinstance(password, unicode):
        password = password.decode('utf-8')
    return password

#Email server
class SendMail:
    def __init__(self):
        try:
            self._server = smtplib.SMTP("smtp.gmail.com", 587)
            self._server.ehlo()
            self._server.starttls()
            self._server.ehlo()
            self._server.login("username", "password")
        except Exception, e:
            raise Exception("Could connect to pop server - " + str(e))

    def send_mail(self, receipient, subject, message, BCC=None):

        sender = "licensing@authorityfx.com"

        body = string.join((
        "From: %s" % sender,
        "To: %s" % receipient,
        "Subject: %s" % subject,
        "", message
        ), "\r\n")

        try:
            if BCC!=None:
                toaddrs = [receipient] + [BCC]
            else:
                toaddrs = [receipient]
            self._server.sendmail(sender, toaddrs, body)
        except Exception, e:
            raise Exception("Could not send email - " + str(e))


class MailBox:

    def __init__(self):

        self._host = 'imap.gmail.com'
        self._port = 993
        self._user = 'username'
        self._pass = 'password'

        try:
            self._imap = imaplib.IMAP4_SSL(self._host, self._port)
            self._imap.login(self._user, self._pass)
            self._imap.select('Inbox')
        except Exception, e:
            print e

        self._parse_pool = Queue.Queue(0)

    def parse(self):

        try:
            unread = self._imap.uid('search', None,'UnSeen')[1][0].split()

            #For each unread email, fetch header
            for email in unread:
                header_raw = self._imap.uid('fetch', email, '(BODY[HEADER])')[1][0][1]
                parser = HeaderParser()
                header = parser.parsestr(header_raw)
                if header['Subject'].find('Notification of payment received') >= 0 and header['Sender']=='sendmail@paypal.com':
                    body = self._imap.uid('fetch', email, '(BODY[TEXT])')[1][0][1]
                    self._parse_pool.put((0, str(unquote(body.replace('=', '%')))))
                elif header['Subject'].find('new_plugin_purchase_from_toolfarm.com') >= 0 and header['From'].find('@toolfarm.com') >=0:
                    body = self._imap.uid('fetch', email, '(BODY[TEXT])')[1][0][1]
                    self._parse_pool.put((1, str(body)))
        except Exception, e:
            print e
        finally:
            #Wait for parse threads to finish
            self._parse_pool.join()

    def get_email(self):
        return self._parse_pool.get()

    def parse_done(self):
        self._parse_pool.task_done()

    def stop(self):
        try:
            self._imap.close()
            self._imap.logout()
        except Exception, e:
            print e

    def __del__(self):
        self.stop()


#Client thread
class ParseThread(threading.Thread):

    def run(self):

        while True:
            #Block for email to parse
            self._email = gmail.get_email()
            #Check if null
            if self._email != None:
                try:
                    if self._email[0] == 0:
                        self.afx_parse()
                    elif self._email[0] == 1:
                        self.toolfarm_parse()
                except Exception, e:
                    print e
                    #If exception send email
                    try:
                        sender = SendMail()
                        sender.send_mail('plugins@authorityfx.com', 'AFX Order Parser Error: ' + str(e), str(e) + "\n\n" + self._email[1])
                    except Exception, e:
                        print e
                finally:
                    #Tell Queue tread in finished
                    gmail.parse_done()

    def afx_parse(self):

        #Find name
        payment_start = self._email[1].find('You received a payment of')
        if payment_start < 0:
            raise Exception("Cannot find 'You received a payment of'")

        pattern = re.compile('from')
        m = pattern.search(self._email[1], payment_start)
        if m:
            name_start = m.end() + 1
        else:
            raise Exception("Cannot find 'from'")

        pattern = re.compile('\(')
        m = pattern.search(self._email[1], name_start)
        if m:
            name_end = m.start()
            user_name = self._email[1][name_start:name_end].title().replace('%', '').strip()
        else:
            raise Exception("Cannot find 'name'")

        #Find shipping address
        pattern = re.compile('shipping address', re.I)
        m = pattern.search(self._email[1])
        if m:
            shipping_addres_end = m.end()
        else:
            raise Exception("Cannot find shipping address")

        #Find Purchase Details
        pattern = re.compile('Purchase Details')
        m = pattern.search(self._email[1])
        if m:
            purchase_details_start = m.end()
        else:
            raise Exception("Cannot find Purchase Details")

        #Find EMAIL ADDRESS
        email_search_region = self._email[1][shipping_addres_end:purchase_details_start]
        pattern = re.compile('([-\.\+\$\w^@]+@(?:[-\w]+\.)+[A-Za-z]{2,4})+')
        m = pattern.search(email_search_region)
        if m:
            email_address = self._email[1][m.start() : m.end()].lower().strip()
        else:
            email_search_region = self._email[1][0:purchase_details_start]
            m = pattern.search(email_search_region)
            if m:
                email_address = self._email[1][m.start() : m.end()].lower().strip()
                if email_address.find('@authorityfx.com') >= 0:
                    raise Exception("Cannot find email address")
            else:
                raise Exception("Cannot find email address")

        #Find transaction id
        pattern = re.compile('(Transaction ID:)(?:\s)+(?:[a-zA-Z0-9]+)')
        m = pattern.search(self._email[1])
        if m:
            transaction_id = self._email[1][m.start() + 16: m.end()].strip()
        else:
            raise Exception("Cannot find transaction id")

        #Connect to database
        db = sqlite3.connect('/home/authorityfx/webapps/tg2env/licensing-portal/devdata.db')
        c = db.cursor()

        c.execute('SELECT user_name FROM tg_user')
        users = c.fetchall()

        user_exists = False
        for user in users:
            if user[0] == email_address:
                user_exists = True

        #Create new user
        if user_exists == False:

            password = ''.join(random.choice(string.letters + string.digits + string.punctuation) for x in xrange(8))
            password_hash = hash_password(password)

            values = (email_address, user_name, password_hash, str(datetime.now()))

            try:
                c.execute('INSERT INTO tg_user (user_name, display_name, password, created) VALUES (?, ?, ?, ?)', values)
                db.commit()
            except Exception, e:
                raise Exception ('Cannot add user - ' + str(e))

            licensing_portal_url = "licensing.authorityfx.com"

            subject = "New Authority FX Licensing Portal Account"
            body =    "Dear " + user_name + ",\n" \
                    + "\n" \
                    + "Please login into your new Authority FX licensing portal account with the following credentials: \n" \
                    + "\n" \
                    + "url: " + licensing_portal_url + "\n" \
                    + "\n" \
                    + "username: " + email_address + "\n" \
                    + "password: " + password + "\n" \
                    + "\n" \
                    + "We suggest that you change you password upon first login.\n" \
                    + "\n" \
                    + "Remember that all purchases are added into our licensing portal under the email address provided at checkout.  "\
                    + "If you want to make puchases using another email address, please ensure that you change your login email via the " \
                    + "settings page prior to making any new purchases.\n" \
                    + "\n" \
                    + "Thanks!"

            try:
                sender = SendMail()
                sender.send_mail(email_address, subject, body, BCC='plugins@authorityfx.com')
            except Exception, e:
                raise Exception ('Could not send new login to ' + user_name + ", " + email_address + ": " + str(e))


        #Look for plugins!
        pattern = re.compile('Purchase Details')
        m = pattern.search(self._email[1])
        if m:
            plugins_start = m.end()
        else:
            raise Exception("Cannot find plugins start")

        pattern = re.compile('Subtotal')
        m = pattern.search(self._email[1], plugins_start)
        if m:
            plugins_end = m.start()
        else:
            raise Exception("Cannot find plugins end")

        plugins = self._email[1][plugins_start:plugins_end].split('Item#')

        licenses = []

        pattern = re.compile('\s*(?:[a-z_]+)\((?:[a-z]+)\)')
        name_pattern = re.compile('(?:[a-z_]+)\(')
        count_pattern = re.compile('(?:Qty:)(?:[0-9]+)')
        for p in plugins:
            m = pattern.search(p)
            if m:
                try:
                    p_name = name_pattern.search(p, m.start())
                    p_count = count_pattern.search(p)

                    name = p[p_name.start():p_name.end()-1].strip()
                    typ = p[p_name.end():m.end()].strip('()').strip()
                    count = int(p[p_count.start()+4:p_count.end()].strip())
                except Exception, e:
                    raise Exception ('Error parsing plugins - ' + str(e))
                try:
                    licenses.append(dict(plugin_id=name, l_type=l_types[typ], floating=False, count=count))
                except Exception, e:
                    raise Exception ('Bad license parse - ' + str(e))


        user_id = c.execute('SELECT user_id FROM tg_user WHERE user_name=?', (email_address,)).fetchall()[0][0]

        #Check if transaction has already been entered
        try:
            values = (user_id, transaction_id)
            c.execute('SELECT COUNT(id) FROM purchase WHERE user_id=? AND transaction_id=?', values)
            existing_count = c.fetchall()[0][0]
        except Exception, e:
            raise Exception ('Cannot query existing licenses - ' + str(e))
        #If transaction_id occurs in db, then this order has already been added
        if existing_count > 0:
            raise Exception('This order has already been processed')

        for license in licenses:

            #Add plugins into plugins into purchase table
            values = (transaction_id, user_id, license['plugin_id'], license['l_type'], license['floating'], license['count'], str(datetime.now()))
            try:
                c.execute('INSERT INTO purchase (transaction_id, user_id, plugin_id, l_type, floating, count, date) VALUES (?, ?, ?, ?, ?, ?, ?)', values)
                db.commit()
            except Exception, e:
                raise Exception ('Cannot add transaction - ' + str(e))

            #Check if this plugin type alreay exists for this user.
            try:
                values = (user_id, license['plugin_id'], license['l_type'], license['floating'])
                c.execute('SELECT COUNT(id) FROM license WHERE user_id=? AND plugin_id=? AND l_type=? AND floating=?', values)
                existing_count = c.fetchall()[0][0]
            except Exception, e:
                raise Exception ('Cannot query existin licenses - ' + str(e))

            #If count is 1, this license type already exists
            if existing_count == 1:
                #Upate existing database entry
                values = (license['count'], license['count'], user_id, license['plugin_id'], license['l_type'], license['floating'])
                try:
                    c.execute('UPDATE license SET count=count + ?, available=available + ? WHERE user_id=? AND plugin_id=? AND l_type=? AND floating=?', values)
                    db.commit()
                except Exception, e:
                    raise Exception ('Cannot update existing license - ' + str(e))
            #Insert new license
            else:
                values = (user_id, license['plugin_id'], license['l_type'], license['floating'], license['count'], license['count'])
                try:
                    c.execute('INSERT INTO license (user_id, plugin_id, l_type, floating, count, available) VALUES (?, ?, ?, ?, ?, ?)', values)
                    db.commit()
                except Exception, e:
                    raise Exception ('Cannot add new license - ' + str(e))


        if len(licenses) > 0:

            licensing_portal_url = 'licensing.authorityfx.com'

            subject = "New Licenses available."
            body =    "Dear " + user_name + ",\n" \
                    + "\n" \
                    + "Please login into your Authority FX licensing portal account to redeem your new licenses \n" \
                    + "\n" \
                    + "url: " + licensing_portal_url + "\n" \
                    + "\n" \
                    + "Thanks!"
            try:
                sender = SendMail()
                sender.send_mail(email_address, subject, body, BCC='plugins@authorityfx.com')
            except Exception, e:
                raise Exception ('Could not send new login to ' + user_name + ", " + email_address + ": " + str(e))
        else:
            raise Exception ('No plugins founds')





    def sku_lookup(self, sku, vendor):

        toolfarm_sku_dict = {'afx-ck-ws':('chroma_key', 'workstation'), \
                    'afx-g-ws':('glow', 'workstation'), \
                    'afx-lg-ws':('lens_glow', 'workstation'), \
                    'afx-d-ws':('defocus', 'workstation'), \
                    'afx-zd-ws':('z_defocus', 'workstation'), \
                    'afx-sc-ws':('soft_clip', 'workstation'), \
                    'afx-c-ws':('clamp', 'workstation'), \
                    'afx-ds-ws':('desaturate', 'workstation') \
                    }

        if vendor=='toolfarm':
            try:
                license = toolfarm_sku_dict[sku]
                return license
            except Exception, e:
                    raise Exception ('Invalid toolfarm SKU:' + str(e))
        else:
            raise Exception ('Invalid vendor:' + str(e))


    def toolfarm_parse(self):

        #Find transaction id
        pattern = re.compile('transaction_id=\{.+\}\s')
        m = pattern.search(self._email[1])
        if m:
            transaction_id = self._email[1][m.start() + 16: m.end() - 2].strip()
        else:
            raise Exception("Cannot find transaction id")

        #Find email_address
        pattern = re.compile('email_address\=\{.+\}\s')
        m = pattern.search(self._email[1])
        if m:
            email_address = self._email[1][m.start() + 15: m.end() - 2].lower().strip()
        else:
            raise Exception("Cannot find email address")

        #Find name
        pattern = re.compile('name\=\{.+\}\s')
        m = pattern.search(self._email[1])
        if m:
            user_name = self._email[1][m.start() + 6: m.end() - 2].strip()
        else:
            raise Exception("Cannot find name")


        #Connect to database
        db = sqlite3.connect('/home/authorityfx/webapps/tg2env/licensing-portal/devdata.db')
        c = db.cursor()

        c.execute('SELECT user_name FROM tg_user')
        users = c.fetchall()

        user_exists = False
        for user in users:
            if user[0] == email_address:
                user_exists = True

        #Create new user
        if user_exists == False:

            password = ''.join(random.choice(string.letters + string.digits + string.punctuation) for x in xrange(8))
            password_hash = hash_password(password)

            values = (email_address, user_name, password_hash, str(datetime.now()))

            try:
                c.execute('INSERT INTO tg_user (user_name, display_name, password, created) VALUES (?, ?, ?, ?)', values)
                db.commit()
            except Exception, e:
                raise Exception ('Cannot add user - ' + str(e))

            licensing_portal_url = "licensing.authorityfx.com"

            subject = "New Authority FX Licensing Portal Account"
            body =    "Dear " + user_name + ",\n" \
                    + "\n" \
                    + "Please login into your new Authority FX licensing portal account with the following credentials: \n" \
                    + "\n" \
                    + licensing_portal_url + "\n" \
                    + "\n" \
                    + "username: " + email_address + "\n" \
                    + "password: " + password + "\n" \
                    + "\n" \
                    + "We suggest that you change you password upon first login.\n" \
                    + "\n" \
                    + "Remember that all purchases are added into our licensing portal under the email address provided at checkout.  "\
                    + "If you want to make puchases using another email address, please ensure that you change your login email via the " \
                    + "settings page prior to making any new purchases.\n" \
                    + "\n" \
                    + "Thanks!"

            try:
                sender = SendMail()
                sender.send_mail(email_address, subject, body, BCC='jason@toolfarm.com')
            except Exception, e:
                raise Exception ('Could not send new login to ' + user_name + ", " + email_address + ": " + str(e))


        #Look for plugins!


        licenses = []

        location = 0
        pattern = re.compile('plugin\=\{.+\}\s')
        name_pattern = re.compile('([a-zA-Z-]+)\,')

        while True:
            p_plugin = pattern.search(self._email[1], location)
            if p_plugin:
                location = p_plugin.end()
                try:
                    p_name = name_pattern.search(self._email[1], p_plugin.start())

                    sku = self._email[1][p_name.start():p_name.end()-1].strip().lower()
                    name, typ = self.sku_lookup(sku, 'toolfarm')

                    count = int(self._email[1][p_name.end()+1:p_plugin.end()-2].strip())
                except Exception, e:
                    raise Exception ('Error parsing plugins - ' + str(e))
                try:
                    licenses.append(dict(plugin_id=name, l_type=l_types[typ], floating=False, count=count))
                except Exception, e:
                    raise Exception ('Bad license parse - ' + str(e))
            else:
                break


        user_id = c.execute('SELECT user_id FROM tg_user WHERE user_name=?', (email_address,)).fetchall()[0][0]

        #Check if transaction has already been entered
        try:
            values = (user_id, transaction_id)
            c.execute('SELECT COUNT(id) FROM purchase WHERE user_id=? AND transaction_id=?', values)
            existing_count = c.fetchall()[0][0]
        except Exception, e:
            raise Exception ('Cannot query existing licenses - ' + str(e))
        #If transaction_id occurs in db, then this order has already been added
        if existing_count > 0:
            raise Exception('This order has already been processed')

        for license in licenses:

            #Add plugins into plugins into purchase table
            values = (transaction_id, user_id, license['plugin_id'], license['l_type'], license['floating'], license['count'], str(datetime.now()))
            try:
                c.execute('INSERT INTO purchase (transaction_id, user_id, plugin_id, l_type, floating, count, date) VALUES (?, ?, ?, ?, ?, ?, ?)', values)
                db.commit()
            except Exception, e:
                raise Exception ('Cannot add transaction - ' + str(e))

            #Check if this plugin type alreay exists for this user.
            try:
                values = (user_id, license['plugin_id'], license['l_type'], license['floating'])
                c.execute('SELECT COUNT(id) FROM license WHERE user_id=? AND plugin_id=? AND l_type=? AND floating=?', values)
                existing_count = c.fetchall()[0][0]
            except Exception, e:
                raise Exception ('Cannot query existin licenses - ' + str(e))

            #If count is 1, this license type already exists
            if existing_count == 1:
                #Upate existing database entry
                values = (license['count'], license['count'], user_id, license['plugin_id'], license['l_type'], license['floating'])
                try:
                    c.execute('UPDATE license SET count=count + ?, available=available + ? WHERE user_id=? AND plugin_id=? AND l_type=? AND floating=?', values)
                    db.commit()
                except Exception, e:
                    raise Exception ('Cannot update existing license - ' + str(e))
            #Insert new license
            else:
                values = (user_id, license['plugin_id'], license['l_type'], license['floating'], license['count'], license['count'])
                try:
                    c.execute('INSERT INTO license (user_id, plugin_id, l_type, floating, count, available) VALUES (?, ?, ?, ?, ?, ?)', values)
                    db.commit()
                except Exception, e:
                    raise Exception ('Cannot add new license - ' + str(e))


        if len(licenses) > 0:

            licensing_portal_url = 'licensing.authorityfx.com'

            subject = "New Licenses available."
            body =    "Dear " + user_name + ",\n" \
                    + "\n" \
                    + "Please login into your Authority FX licensing portal account to redeem your new licenses \n" \
                    + "\n" \
                    + licensing_portal_url + "\n" \
                    + "\n" \
                    + "Thanks!"
            try:
                sender = SendMail()
                sender.send_mail(email_address, subject, body, BCC='@toolfarm.com')
            except Exception, e:
                raise Exception ('Could not send new login to ' + user_name + ", " + email_address + ": " + str(e))
        else:
            raise Exception ('No plugins found')



gmail = MailBox()

#Client Threads
parse_threads = []
num_threads = 2

#Start client threads
for i in range(num_threads):
    parse_threads.append(ParseThread())
    parse_threads[i].setDaemon(True)
    parse_threads[i].start()

gmail.parse()
