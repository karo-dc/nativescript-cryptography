import { Cryptography } from 'nativescript-cryptography';
// console.log(new Cryptography().message);
/*
In NativeScript, a file with the same name as an XML file is known as
a code-behind file. The code-behind is a great place to place your view
logic, and to set up your page’s data binding.
*/

import { NavigatedData, Page } from "tns-core-modules/ui/page";

import { MainViewModel } from "./main-view-model";

export function onNavigatingTo(args: NavigatedData) {
  const page = <Page>args.object;

  page.bindingContext = new MainViewModel();
}
