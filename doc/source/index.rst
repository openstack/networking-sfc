..
      Copyright 2015 Futurewei. All rights reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)

.. the main title comes from README.rst

.. NOTE(amotoki): The content of this file is NOT rendered in the generated
   PDF file. This is because toctree_only=False is specified in latex_documents
   in doc/source/conf.py to get a better structure of the PDF doc.

.. NOTE(amotoki): The following "include" and hidden "toctree" directives
   are the magic to make both HTML and PDF versions of the document properly.
   The latex builder recognizes the doc structure based on "toctree"
   directive, while we would like to show the content of README file in
   the top page of the HTML version.

.. include:: readme.rst

.. toctree::
   :hidden:

   readme

Contents
--------

.. toctree::
   :maxdepth: 2

   install/index
   user/index
   configuration/index

.. toctree::
   :maxdepth: 3

   contributor/index

.. only:: html

   .. rubric:: Indices and tables

   * :ref:`genindex`
   * :ref:`search`
