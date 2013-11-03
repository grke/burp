/*
 * Minimal replacement for class CComPtr and CComBSTR
 * Based on common public IUnknown interface only
 */

template <class T> class CComPtr
{
public:
        T* p;
        CComPtr() { p=NULL; }
        ~CComPtr() { if (p) p->Release(); }
};

class CComBSTR
{
public:
        BSTR p;
        CComBSTR() { p = NULL; }
        ~CComBSTR() { ::SysFreeString(p); }
        BSTR* operator&() { return &p; }
};
