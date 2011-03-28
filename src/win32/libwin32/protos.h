/*
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version two of the GNU General Public
   License as published by the Free Software Foundation, which is 
   listed in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.
*/

#define log_error_message(msg) LogErrorMsg((msg), __FILE__, __LINE__)

extern int BurpAppMain();
extern void LogErrorMsg(const char *msg, const char *fname, int lineno);

extern int BurpMain(int argc, char *argv[]);
extern BOOL ReportStatus(DWORD state, DWORD exitcode, DWORD waithint);
extern void d_msg(const char *, int, int, const char *, ...);
extern char *bac_status(char *buf, int buf_len);


/* service.cpp */
bool postToBurp(UINT message, WPARAM wParam, LPARAM lParam);
bool isAService();
int installService(const char *svc);
int removeService();
int stopRunningBurp();
int burpServiceMain();


/* Globals */
extern DWORD service_error;
extern bool have_service_api;
extern HINSTANCE appInstance;
